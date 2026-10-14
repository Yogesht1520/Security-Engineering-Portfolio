"""
tests/test_v2_analyst_feedback.py — Tests for interactive SOC analyst console actions
====================================================================================
Verifies:
  - Whitelisting / False-Positive suppression endpoint
  - Early unblock / manual expiry endpoint
  - Database status and enforcement state updates
  - 404 handling on non-existent targets
  - SIEM event generation for analyst manual overrides
"""
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from config import load_config
from dashboard.app import create_app
from models import ScoredIP
from storage.db import ThreatIntelDB


@pytest.fixture
def app_and_db(tmp_path):
    db_file = tmp_path / "dashboard_soc.db"
    audit_file = tmp_path / "audit.jsonl"
    siem_file = tmp_path / "siem.jsonl"

    cfg = load_config()
    cfg["storage"]["db_path"] = str(db_file)
    cfg["audit"]["log_path"] = str(audit_file)
    cfg["siem"] = {
        "enabled": True,
        "mode": "file",
        "format": "json",
        "file_path": str(siem_file),
    }

    now = datetime.now(timezone.utc)
    with ThreatIntelDB(str(db_file)) as db:
        db.init_schema()
        # Seed an active blocked indicator
        scored = ScoredIP(
            ip="198.51.100.42",
            combined_score=85.0,
            sources=["abuseipdb"],
            category="bruteforce",
            first_seen=now,
            expires_at=now,
        )
        db.upsert(scored, status="blocked", reason="Threshold met")
        db.set_enforced("198.51.100.42", True)

    app = create_app(cfg)
    app.config["TESTING"] = True
    return app, str(db_file), str(siem_file)


class TestAnalystSocActions:
    def test_whitelist_indicator_endpoint(self, app_and_db):
        app, db_path, siem_file = app_and_db
        client = app.test_client()

        resp = client.post(
            "/api/indicators/198.51.100.42/whitelist",
            json={"reason": "Corporate NAT gateway false positive", "analyst": "Yogesh"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["status"] == "whitelisted"

        # Verify database record updated
        with ThreatIntelDB(db_path) as db:
            row = db.get_by_ip("198.51.100.42")
            assert row is not None
            assert row["status"] == "whitelisted"
            assert row["enforced"] == 0
            assert "Corporate NAT gateway" in row["reason"]

        # Verify SIEM audit event emitted
        lines = Path(siem_file).read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 1
        ev = json.loads(lines[-1])
        assert ev["event_type"] == "threat_intel.analyst_override"
        assert ev["data"]["action"] == "whitelist"
        assert ev["data"]["details"]["analyst"] == "Yogesh"

    def test_unblock_indicator_endpoint(self, app_and_db):
        app, db_path, siem_file = app_and_db
        client = app.test_client()

        resp = client.post(
            "/api/indicators/198.51.100.42/unblock",
            json={"reason": "Customer ticket verified harmless", "analyst": "SOC Lead"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["status"] == "expired"

        with ThreatIntelDB(db_path) as db:
            row = db.get_by_ip("198.51.100.42")
            assert row is not None
            assert row["status"] == "expired"
            assert row["enforced"] == 0
            assert "EARLY UNBLOCK by SOC Lead" in row["reason"]

    def test_nonexistent_indicator_returns_404(self, app_and_db):
        app, _, _ = app_and_db
        client = app.test_client()

        resp = client.post(
            "/api/indicators/203.0.113.99/whitelist",
            json={"reason": "Not here"},
        )
        assert resp.status_code == 404
        assert resp.get_json()["success"] is False
