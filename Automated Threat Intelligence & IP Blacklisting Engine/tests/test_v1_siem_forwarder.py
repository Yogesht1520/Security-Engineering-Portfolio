"""
tests/test_v1_siem_forwarder.py — Tests for SIEM & Wazuh event forwarding layer
================================================================================
Verifies:
  - Wazuh structured JSON serialization
  - ArcSight/QRadar Common Event Format (CEF) serialization
  - File transport delivery (JSON Lines)
  - Syslog UDP transport delivery
  - Non-fatal fault tolerance when SIEM endpoints are unreachable
  - Full pipeline integration with SIEM streaming enabled
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import threading

import pytest

from config import load_config
from main import run_pipeline, run_reconciliation
from models import RawIndicator
from siem.forwarder import SiemEvent, SiemForwarder
from storage.db import ThreatIntelDB


class TestSiemEventSerialization:
    def test_wazuh_json_event_formatting(self):
        event = SiemEvent(
            event_type="threat_intel.block",
            severity="high",
            summary="Threat intelligence block enforced for 198.51.100.42",
            target_ip="198.51.100.42",
            score=87.54,
            category="brute-force",
            sources=["abuseipdb", "otx"],
            action="block",
            reason="Corroborated high-confidence threat",
            details={"evidence_items": [{"source": "abuseipdb", "conf": 90}]},
        )
        payload = event.to_wazuh_dict()

        assert payload["integration"] == "threat_intel_engine"
        assert payload["event_type"] == "threat_intel.block"
        assert payload["severity"] == "high"
        assert payload["data"]["src_ip"] == "198.51.100.42"
        assert payload["data"]["confidence_score"] == 87.54
        assert payload["data"]["category"] == "brute-force"
        assert payload["data"]["threat_sources"] == ["abuseipdb", "otx"]
        assert payload["data"]["action"] == "block"
        assert len(payload["data"]["details"]["evidence_items"]) == 1

    def test_cef_event_formatting(self):
        event = SiemEvent(
            event_type="threat_intel.block",
            severity="critical",
            summary="Critical C2 node blocked",
            target_ip="203.0.113.10",
            score=99.0,
            category="c2",
            sources=["spamhaus"],
            action="block",
            reason="Spamhaus DROP listed",
        )
        cef_str = event.to_cef()

        assert cef_str.startswith("CEF:0|SecurityEngineering|ThreatIntelEngine|1.0|threat_intel.block|")
        assert "|10|" in cef_str  # critical mapped to 10
        assert "src=203.0.113.10" in cef_str
        assert "cn1=99.0" in cef_str
        assert "cn1Label=ConfidenceScore" in cef_str
        assert "cat=c2" in cef_str
        assert "cs1=spamhaus" in cef_str
        assert "act=block" in cef_str


class TestSiemForwarderTransports:
    def test_file_transport_delivery(self, tmp_path):
        event_file = tmp_path / "siem_events.jsonl"
        forwarder = SiemForwarder({
            "enabled": True,
            "mode": "file",
            "format": "json",
            "file_path": str(event_file),
        })

        # Emit various events
        assert forwarder.emit_block(
            ip="198.51.100.5",
            score=82.0,
            sources=["abuseipdb"],
            category="scanner",
            reason="Active scanner detected",
        ) is True

        assert forwarder.emit_unblock(
            ip="198.51.100.5",
            reason="TTL expired",
        ) is True

        assert forwarder.emit_circuit_breaker(
            violation="Rate of change exceeded",
            planned_adds=600,
            planned_removes=0,
            current_size=100,
        ) is True

        assert forwarder.emit_feed_status(
            feed_name="abuseipdb",
            healthy=True,
            duration_ms=120.5,
        ) is True

        assert forwarder.emit_drift(
            detected_orphans=["198.51.100.99"],
            missing_in_fw=["198.51.100.5"],
        ) is True

        assert event_file.exists()
        lines = event_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 5

        events = [json.loads(line) for line in lines]
        types = [ev["event_type"] for ev in events]
        assert "threat_intel.block" in types
        assert "threat_intel.unblock" in types
        assert "threat_intel.circuit_breaker" in types
        assert "threat_intel.feed_status" in types
        assert "threat_intel.drift" in types

    def test_mock_mode_buffering(self):
        forwarder = SiemForwarder({"enabled": False, "mode": "mock"})
        forwarder.emit_block(
            ip="198.51.100.20",
            score=75.0,
            sources=["otx"],
            category="malware",
            reason="Pulse match",
        )
        assert len(forwarder.emitted_events) == 1
        assert forwarder.emitted_events[0].target_ip == "198.51.100.20"

    def test_syslog_udp_transport(self):
        # Ephemeral UDP server
        received_packets: list[str] = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        _, port = sock.getsockname()
        sock.settimeout(2.0)

        def _listener():
            try:
                data, _ = sock.recvfrom(4096)
                received_packets.append(data.decode("utf-8"))
            except Exception:
                pass
            finally:
                sock.close()

        thread = threading.Thread(target=_listener)
        thread.start()

        forwarder = SiemForwarder({
            "enabled": True,
            "mode": "syslog_udp",
            "format": "cef",
            "syslog_host": "127.0.0.1",
            "syslog_port": port,
        })
        forwarder.emit_block(
            ip="198.51.100.77",
            score=91.0,
            sources=["abuseipdb"],
            category="botnet",
            reason="High abuse confidence",
        )
        thread.join(timeout=3.0)

        assert len(received_packets) == 1
        assert "198.51.100.77" in received_packets[0]
        assert "CEF:0|" in received_packets[0]

    def test_non_fatal_error_handling_when_endpoint_down(self):
        # Pointing to an invalid closed TCP port must not crash or throw unhandled exceptions
        forwarder = SiemForwarder({
            "enabled": True,
            "mode": "syslog_tcp",
            "syslog_host": "127.0.0.1",
            "syslog_port": 1,  # Typically closed port
        })
        # Should gracefully return False without raising
        success = forwarder.emit_block(
            ip="198.51.100.1",
            score=80.0,
            sources=["abuseipdb"],
            category="bad",
            reason="test",
        )
        assert success is False


class TestPipelineSiemIntegration:
    def test_pipeline_emits_siem_events_end_to_end(self, tmp_path):
        cfg = load_config()
        event_file = tmp_path / "pipeline_siem_events.jsonl"
        db_file = tmp_path / "test.db"

        cfg["storage"]["db_path"] = str(db_file)
        cfg["siem"] = {
            "enabled": True,
            "mode": "file",
            "format": "json",
            "file_path": str(event_file),
        }
        cfg["policy"]["confidence_threshold"] = 70

        now = datetime.now(timezone.utc)
        indicators = [
            RawIndicator("198.51.100.50", "abuseipdb", 85.0, "bruteforce", now),
            RawIndicator("198.51.100.50", "otx", 80.0, "bruteforce", now),
        ]

        decisions = run_pipeline(cfg, indicators=indicators, dry_run=True)
        assert len(decisions) == 1
        assert decisions[0].action == "block"

        # Verify SIEM events were generated and written
        assert event_file.exists()
        lines = [json.loads(l) for l in event_file.read_text(encoding="utf-8").strip().splitlines()]
        assert len(lines) >= 1

        event_types = {l["event_type"] for l in lines}
        # Feed status and block events should have been captured
        assert "threat_intel.feed_status" in event_types or "threat_intel.block" in event_types
