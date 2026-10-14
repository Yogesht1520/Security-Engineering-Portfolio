"""
tests/test_v1_reporting_digest.py — Tests for scheduled run digest and webhook alerts
=====================================================================================
Verifies:
  - Executive Markdown run report generation
  - Circuit breaker visual callout formatting
  - Slack/Discord Block Kit webhook formatting
  - ReportManager file archiving (latest_run.md and timestamped run_<id>.md)
  - HTTP webhook delivery with mock server
  - Pipeline integration end-to-end report generation
"""
from datetime import datetime, timezone
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading

import pytest

from config import load_config
from main import run_pipeline
from models import RawIndicator
from reporting.digest import FeedDigest, ReportManager, RunDigest


class TestRunDigestFormatting:
    def test_markdown_digest_clean_run(self):
        digest = RunDigest(
            run_id="run-12345",
            timestamp=datetime(2026, 10, 14, 18, 0, 0, tzinfo=timezone.utc),
            duration_seconds=3.42,
            operational_state="HEALTHY",
            collected_raw=2200,
            unique_ips=2200,
            blocked_count=150,
            log_only_count=2050,
            enforced_added=150,
            enforced_removed=2,
            enforced_skipped=0,
            expired_count=2,
            total_active_in_db=150,
            feeds=[
                FeedDigest("abuseipdb", True, 120.0, 500, 0),
                FeedDigest("otx", True, 350.0, 20, 0),
                FeedDigest("spamhaus", True, 200.0, 1680, 0),
            ],
        )
        md = digest.to_markdown()

        assert "# 🟢 Threat Intelligence Pipeline Run Report" in md
        assert "run-12345" in md
        assert "| Raw Indicators | 2200 |" in md
        assert "| Policy Blocks | 150 |" in md
        assert "| **abuseipdb** | ✅ Healthy | 120.0ms |" in md
        assert "[!CAUTION]" not in md  # Not tripped

    def test_markdown_digest_circuit_breaker_alert(self):
        digest = RunDigest(
            run_id="run-alert",
            timestamp=datetime.now(timezone.utc),
            duration_seconds=1.2,
            operational_state="HEALTHY",
            collected_raw=1000,
            unique_ips=1000,
            blocked_count=800,
            log_only_count=200,
            enforced_added=0,
            enforced_removed=0,
            enforced_skipped=0,
            expired_count=0,
            total_active_in_db=50,
            circuit_breaker_tripped=True,
            circuit_breaker_reason="Planned additions (+800) exceed quota (500)",
        )
        md = digest.to_markdown()

        assert "# 🔴 Threat Intelligence Pipeline Run Report" in md
        assert "> [!CAUTION]" in md
        assert "SAFETY CIRCUIT BREAKER TRIGGERED" in md
        assert "Planned additions (+800) exceed quota (500)" in md

    def test_slack_webhook_payload(self):
        digest = RunDigest(
            run_id="run-webhook",
            timestamp=datetime.now(timezone.utc),
            duration_seconds=2.5,
            operational_state="HEALTHY",
            collected_raw=500,
            unique_ips=500,
            blocked_count=10,
            log_only_count=490,
            enforced_added=10,
            enforced_removed=0,
            enforced_skipped=0,
            expired_count=0,
            total_active_in_db=10,
        )
        payload = digest.to_slack_webhook_payload()
        assert "text" in payload
        assert "blocks" in payload
        assert len(payload["blocks"]) >= 1


class TestReportManagerArchival:
    def test_save_markdown_digest_creates_files(self, tmp_path):
        reports_dir = tmp_path / "reports"
        mgr = ReportManager({"reports_dir": str(reports_dir)})

        digest = RunDigest(
            run_id="test-run-abc",
            timestamp=datetime.now(timezone.utc),
            duration_seconds=1.0,
            operational_state="HEALTHY",
            collected_raw=10,
            unique_ips=10,
            blocked_count=1,
            log_only_count=9,
            enforced_added=1,
            enforced_removed=0,
            enforced_skipped=0,
            expired_count=0,
            total_active_in_db=1,
        )

        latest_path = mgr.save_markdown_digest(digest)
        assert latest_path.exists()
        assert latest_path.name == "latest_run.md"

        archive_path = reports_dir / "run_test-run-abc.md"
        assert archive_path.exists()

    def test_webhook_dispatch_success(self):
        received_requests: list[dict] = []

        class MockHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode("utf-8")
                received_requests.append(json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), MockHandler)
        port = server.server_port
        thread = threading.Thread(target=server.handle_request)
        thread.start()

        mgr = ReportManager({"webhook_url": f"http://127.0.0.1:{port}/webhook"})
        digest = RunDigest(
            run_id="wh-test",
            timestamp=datetime.now(timezone.utc),
            duration_seconds=1.0,
            operational_state="HEALTHY",
            collected_raw=10,
            unique_ips=10,
            blocked_count=1,
            log_only_count=9,
            enforced_added=1,
            enforced_removed=0,
            enforced_skipped=0,
            expired_count=0,
            total_active_in_db=1,
        )
        assert mgr.dispatch_webhook(digest) is True
        thread.join(timeout=2.0)
        server.server_close()

        assert len(received_requests) == 1
        assert "Threat Intel Engine Run" in received_requests[0]["text"]


class TestPipelineReportingIntegration:
    def test_pipeline_generates_markdown_digest_end_to_end(self, tmp_path):
        cfg = load_config()
        reports_dir = tmp_path / "reports"
        db_file = tmp_path / "test.db"

        cfg["storage"]["db_path"] = str(db_file)
        cfg["reporting"] = {
            "enabled": True,
            "reports_dir": str(reports_dir),
            "webhook_url": None,
        }
        cfg["policy"]["confidence_threshold"] = 70

        now = datetime.now(timezone.utc)
        indicators = [
            RawIndicator("198.51.100.88", "abuseipdb", 95.0, "bruteforce", now),
        ]

        decisions = run_pipeline(cfg, indicators=indicators, dry_run=True)
        assert len(decisions) == 1

        latest_report = reports_dir / "latest_run.md"
        assert latest_report.exists()
        content = latest_report.read_text(encoding="utf-8")
        assert "Pipeline Execution Metrics" in content
        assert "Policy Blocks" in content
