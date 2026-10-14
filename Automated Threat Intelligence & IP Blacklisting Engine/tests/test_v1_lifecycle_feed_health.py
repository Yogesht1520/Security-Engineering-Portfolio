"""
tests/test_v1_lifecycle_feed_health.py — Tests for extended indicator lifecycle and feed health tracking
"""
from datetime import datetime, timezone

from dashboard.app import create_app
from models import ScoredIP
from storage.db import ThreatIntelDB


class TestLifecycleTracking:
    def test_lifecycle_timestamps_initial_upsert(self, tmp_path):
        db_path = str(tmp_path / "lifecycle.db")
        now = datetime.now(timezone.utc)

        with ThreatIntelDB(db_path) as db:
            db.init_schema()
            scored = ScoredIP(
                ip="198.51.100.42",
                combined_score=85.0,
                sources=["abuseipdb"],
                category="bruteforce",
                first_seen=now,
                expires_at=now,
                evidence=[{"source": "abuseipdb", "conf": 85}],
            )
            db.upsert(scored, status="blocked", reason="Score exceeds threshold")

            row = db.get_by_ip("198.51.100.42")
            assert row is not None
            assert row["first_seen"] is not None
            assert row["last_seen"] is not None
            assert row["status"] == "blocked"
            assert row["reason"] == "Score exceeds threshold"
            assert len(row["evidence"]) == 1

    def test_independent_corroboration_advances_last_confirmed(self, tmp_path):
        db_path = str(tmp_path / "lifecycle.db")
        now = datetime.now(timezone.utc)

        with ThreatIntelDB(db_path) as db:
            db.init_schema()
            # 1. First seen with single source
            ip1 = ScoredIP("198.51.100.42", 70.0, sources=["abuseipdb"], first_seen=now)
            db.upsert(ip1)
            row1 = db.get_by_ip("198.51.100.42")
            initial_confirmed = row1["last_confirmed"]

            # 2. Repeated stale single-source update: should NOT advance last_confirmed
            ip2 = ScoredIP("198.51.100.42", 70.0, sources=["abuseipdb"], first_seen=now)
            db.upsert(ip2)
            row2 = db.get_by_ip("198.51.100.42")
            assert row2["last_confirmed"] == initial_confirmed

            # 3. Corroborated by second source (abuseipdb + otx): advances last_confirmed
            ip3 = ScoredIP("198.51.100.42", 85.0, sources=["abuseipdb", "otx"], first_seen=now)
            db.upsert(ip3)
            row3 = db.get_by_ip("198.51.100.42")
            assert row3["source_count"] == 2
            assert row3["last_confirmed"] is not None


class TestFeedHealthTelemetry:
    def test_record_and_retrieve_feed_health(self, tmp_path):
        db_path = str(tmp_path / "health.db")

        with ThreatIntelDB(db_path) as db:
            db.init_schema()
            db.record_feed_health(
                feed_name="abuseipdb",
                status="Healthy",
                duration_ms=250.5,
                indicators_received=500,
                rejected_count=3,
                error_message=None,
            )
            db.record_feed_health(
                feed_name="otx",
                status="Degraded",
                duration_ms=1200.0,
                indicators_received=45,
                rejected_count=0,
                error_message="HTTP 429 Rate Limit Warning",
            )

            records = db.get_feed_health()
            assert len(records) == 2
            abuse = next(r for r in records if r["feed_name"] == "abuseipdb")
            assert abuse["status"] == "Healthy"
            assert abuse["indicators_received"] == 500
            assert abuse["rejected_count"] == 3

            otx = next(r for r in records if r["feed_name"] == "otx")
            assert otx["status"] == "Degraded"
            assert "429" in otx["error_message"]

    def test_dashboard_api_feed_health_endpoint(self, tmp_path):
        db_path = str(tmp_path / "dash_health.db")
        with ThreatIntelDB(db_path) as db:
            db.init_schema()
            db.record_feed_health("spamhaus", "Healthy", 850.0, 1600, 2)

        app = create_app(db_path=db_path)
        client = app.test_client()

        res = client.get("/api/feed-health")
        assert res.status_code == 200
        data = res.get_json()
        assert len(data) == 1
        assert data[0]["feed_name"] == "spamhaus"
        assert data[0]["indicators_received"] == 1600
