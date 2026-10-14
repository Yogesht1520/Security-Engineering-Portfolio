"""
siem/forwarder.py — SIEM and Wazuh event forwarding layer
==========================================================
Bridges the Threat Intelligence Engine with SIEM platforms (e.g. Wazuh SIEM,
Syslog, Splunk, Elastic) by streaming structured security events:
  - Blacklist enforcement (Blocks)
  - TTL expiration and unblocks
  - Circuit breaker trips and safety halts
  - Feed health state transitions (Degraded, Outages)
  - Desired-vs-actual state drift detection

Supports:
  - Wazuh JSON Lines (for Wazuh agent localfile monitoring)
  - Syslog UDP / TCP (RFC 5424 / RFC 3164)
  - Common Event Format (CEF) serialization
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import socket
from typing import Any, Literal

logger = logging.getLogger(__name__)

SeverityLevel = Literal["info", "warning", "high", "critical"]
SiemFormat = Literal["json", "cef"]
SiemMode = Literal["file", "syslog_udp", "syslog_tcp", "mock"]


@dataclass
class SiemEvent:
    """Standardized threat intelligence security event."""
    event_type: str
    severity: SeverityLevel
    summary: str
    target_ip: str | None = None
    score: float | None = None
    category: str | None = None
    sources: list[str] = field(default_factory=list)
    action: str | None = None
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_wazuh_dict(self) -> dict[str, Any]:
        """Format as a rich, structured Wazuh/SIEM JSON payload."""
        payload: dict[str, Any] = {
            "timestamp": self.timestamp.isoformat(),
            "integration": "threat_intel_engine",
            "event_type": self.event_type,
            "severity": self.severity,
            "summary": self.summary,
            "data": {
                "action": self.action,
                "reason": self.reason,
            },
        }
        if self.target_ip:
            payload["data"]["src_ip"] = self.target_ip
        if self.score is not None:
            payload["data"]["confidence_score"] = round(self.score, 2)
        if self.category:
            payload["data"]["category"] = self.category
        if self.sources:
            payload["data"]["threat_sources"] = list(self.sources)
        if self.details:
            payload["data"]["details"] = self.details
        return payload

    def to_cef(self) -> str:
        """Format as Common Event Format (CEF:0)."""
        sev_map: dict[SeverityLevel, int] = {
            "info": 1,
            "warning": 4,
            "high": 7,
            "critical": 10,
        }
        severity_num = sev_map.get(self.severity, 1)

        # Standard CEF header
        header = f"CEF:0|SecurityEngineering|ThreatIntelEngine|1.0|{self.event_type}|{self.summary}|{severity_num}|"

        # Extensions
        exts: list[str] = []
        if self.target_ip:
            exts.append(f"src={self.target_ip}")
        if self.score is not None:
            exts.append(f"cn1={self.score:.1f}")
            exts.append("cn1Label=ConfidenceScore")
        if self.category:
            exts.append(f"cat={self.category}")
        if self.sources:
            exts.append(f"cs1={','.join(self.sources)}")
            exts.append("cs1Label=Sources")
        if self.action:
            exts.append(f"act={self.action}")
        if self.reason:
            exts.append(f"msg={self.reason}")

        return header + " ".join(exts)


class SiemForwarder:
    """
    Handles buffering, formatting, and forwarding of security events
    to SIEM collectors or local log ingest queues.
    """

    def __init__(self, siem_cfg: dict[str, Any] | None = None) -> None:
        cfg = siem_cfg or {}
        self.enabled: bool = bool(cfg.get("enabled", False))
        self.mode: SiemMode = cfg.get("mode", "file")
        self.format: SiemFormat = cfg.get("format", "json")
        self.file_path: Path = Path(cfg.get("file_path", "data/siem_events.jsonl"))
        self.syslog_host: str = str(cfg.get("syslog_host", "127.0.0.1"))
        self.syslog_port: int = int(cfg.get("syslog_port", 514))
        self.emitted_events: list[SiemEvent] = []  # In-memory buffer for verification / mock mode

    def emit(self, event: SiemEvent) -> bool:
        """
        Deliver a single SIEM event. Gracefully swallows network/file errors
        to guarantee engine operations never halt on telemetry failures.
        """
        self.emitted_events.append(event)
        if not self.enabled and self.mode != "mock":
            return False

        try:
            formatted = event.to_cef() if self.format == "cef" else json.dumps(event.to_wazuh_dict())

            if self.mode == "file":
                self._write_file(formatted)
            elif self.mode == "syslog_udp":
                self._send_udp(formatted)
            elif self.mode == "syslog_tcp":
                self._send_tcp(formatted)
            elif self.mode == "mock":
                pass
            return True
        except Exception as exc:
            logger.warning("SIEM forwarder error (non-fatal): %s", exc)
            return False

    def emit_block(
        self,
        ip: str,
        score: float,
        sources: list[str],
        category: str,
        reason: str,
        evidence: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Emit an active firewall block enforcement event."""
        return self.emit(SiemEvent(
            event_type="threat_intel.block",
            severity="high",
            summary=f"Threat intelligence block enforced for {ip}",
            target_ip=ip,
            score=score,
            sources=sources,
            category=category,
            action="block",
            reason=reason,
            details={"evidence_items": evidence or []},
        ))

    def emit_unblock(
        self,
        ip: str,
        reason: str,
        orig_sources: list[str] | None = None,
    ) -> bool:
        """Emit an expiration / unblock enforcement event."""
        return self.emit(SiemEvent(
            event_type="threat_intel.unblock",
            severity="info",
            summary=f"Threat intelligence block expired/removed for {ip}",
            target_ip=ip,
            sources=orig_sources or [],
            action="unblock",
            reason=reason,
        ))

    def emit_circuit_breaker(
        self,
        violation: str,
        planned_adds: int,
        planned_removes: int,
        current_size: int,
    ) -> bool:
        """Emit a critical safety circuit breaker trip event."""
        return self.emit(SiemEvent(
            event_type="threat_intel.circuit_breaker",
            severity="critical",
            summary=f"Safety circuit breaker triggered: {violation}",
            action="halt",
            reason=violation,
            details={
                "planned_additions": planned_adds,
                "planned_removals": planned_removes,
                "current_blocklist_size": current_size,
            },
        ))

    def emit_feed_status(
        self,
        feed_name: str,
        healthy: bool,
        duration_ms: float,
        error: str | None = None,
    ) -> bool:
        """Emit a threat intelligence feed availability state event."""
        severity: SeverityLevel = "info" if healthy else "warning"
        summary = f"Threat feed '{feed_name}' sync {'succeeded' if healthy else 'failed'}"
        return self.emit(SiemEvent(
            event_type="threat_intel.feed_status",
            severity=severity,
            summary=summary,
            action="feed_sync",
            reason=error or "Normal synchronization",
            details={
                "feed_name": feed_name,
                "healthy": healthy,
                "duration_ms": duration_ms,
                "error": error,
            },
        ))

    def emit_drift(
        self,
        detected_orphans: list[str],
        missing_in_fw: list[str],
    ) -> bool:
        """Emit an infrastructure reconciliation drift event."""
        drift_count = len(detected_orphans) + len(missing_in_fw)
        if drift_count == 0:
            return False

        return self.emit(SiemEvent(
            event_type="threat_intel.drift",
            severity="warning",
            summary=f"Firewall state drift detected: {drift_count} discrepanc{'y' if drift_count == 1 else 'ies'}",
            action="reconcile",
            reason="State drift detected between SQLite and firewall",
            details={
                "orphan_firewall_rules": detected_orphans,
                "missing_firewall_rules": missing_in_fw,
            },
        ))

    def emit_analyst_action(
        self,
        ip: str,
        action: str,
        reason: str,
        analyst: str = "SOC Analyst",
    ) -> bool:
        """Emit an interactive analyst manual override event."""
        return self.emit(SiemEvent(
            event_type="threat_intel.analyst_override",
            severity="warning" if action == "whitelist" else "info",
            summary=f"Analyst {action} override applied for {ip} by {analyst}",
            target_ip=ip,
            action=action,
            reason=reason,
            details={"analyst": analyst},
        ))

    def emit_batch(self, events: list[SiemEvent]) -> int:
        """Deliver a batch of events, returning successfully dispatched count."""
        count = 0
        for ev in events:
            if self.emit(ev):
                count += 1
        return count

    # ── Private transport implementations ────────────────────────────────────

    def _write_file(self, content: str) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(content + "\n")

    def _send_udp(self, content: str) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(content.encode("utf-8"), (self.syslog_host, self.syslog_port))
        finally:
            sock.close()

    def _send_tcp(self, content: str) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((self.syslog_host, self.syslog_port))
            sock.sendall((content + "\n").encode("utf-8"))
        finally:
            sock.close()
