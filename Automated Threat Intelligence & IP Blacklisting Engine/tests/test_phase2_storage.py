"""
tests/test_phase2_storage.py — Unit tests for ThreatIntelDB SQLite storage
"""
from datetime import datetime, timedelta, timezone
import pytest

from models import ScoredIP
from storage.db import ThreatIntelDB


@pytest.fixture
def db():
    database = ThreatIntelDB(":memory:")
    database.init_schema()
    yield database
    database.close()


def _make_scored_ip(
    ip: str = "1.2.3.4",
    score: float = 85.0,
    sources: list[str] | None = None,
    category: str = "brute-force",
    first_seen: datetime | None = None,
    expires_at: datetime | None = None,
) -> ScoredIP:
    now = datetime.now(timezone.utc)
    return ScoredIP(
        ip=ip,
        combined_score=score,
        sources=sources or ["abuseipdb"],
        category=category,
        first_seen=first_seen or now,
        expires_at=expires_at or (now + timedelta(days=7)),
    )


class TestThreatIntelDB:
    def test_init_creates_table(self, db: ThreatIntelDB):
        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scored_ips'")
        row = cursor.fetchone()
        assert row is not None

    def test_upsert_inserts_new_row(self, db: ThreatIntelDB):
        record = _make_scored_ip(ip="1.2.3.4", score=88.5)
        res = db.upsert(record)
        assert res == "inserted"

        row = db.get_by_ip("1.2.3.4")
        assert row is not None
        assert row["ip"] == "1.2.3.4"
        assert row["combined_score"] == 88.5
        assert row["enforced"] == 0

    def test_upsert_updates_existing_row(self, db: ThreatIntelDB):
        rec1 = _make_scored_ip(ip="1.2.3.4", score=80.0)
        db.upsert(rec1)

        rec2 = _make_scored_ip(ip="1.2.3.4", score=95.0, sources=["abuseipdb", "otx"])
        res = db.upsert(rec2)
        assert res == "updated"

        row = db.get_by_ip("1.2.3.4")
        assert row is not None
        assert row["combined_score"] == 95.0
        assert row["sources"] == ["abuseipdb", "otx"]

    def test_first_seen_never_overwritten(self, db: ThreatIntelDB):
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        db.upsert(_make_scored_ip(ip="1.1.1.1", first_seen=t0))
        initial = db.get_by_ip("1.1.1.1")
        assert initial["first_seen"].startswith("2025-01-01")

        db.upsert(_make_scored_ip(ip="1.1.1.1", first_seen=t1))
        updated = db.get_by_ip("1.1.1.1")
        assert updated["first_seen"].startswith("2025-01-01")

    def test_enforced_flag_preserved_on_upsert(self, db: ThreatIntelDB):
        db.upsert(_make_scored_ip(ip="1.1.1.1"))
        db.set_enforced("1.1.1.1", True)

        row_before = db.get_by_ip("1.1.1.1")
        assert row_before["enforced"] == 1

        # Re-upserting must NOT reset enforced back to 0
        db.upsert(_make_scored_ip(ip="1.1.1.1", score=99.0))
        row_after = db.get_by_ip("1.1.1.1")
        assert row_after["enforced"] == 1
        assert row_after["combined_score"] == 99.0

    def test_get_expired_returns_only_expired(self, db: ThreatIntelDB):
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=2)
        future = now + timedelta(days=2)

        db.upsert(_make_scored_ip(ip="10.0.0.1", expires_at=past))
        db.upsert(_make_scored_ip(ip="10.0.0.2", expires_at=future))

        expired = db.get_expired(now)
        assert len(expired) == 1
        assert expired[0]["ip"] == "10.0.0.1"

    def test_get_active_excludes_expired(self, db: ThreatIntelDB):
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=2)
        future = now + timedelta(days=2)

        db.upsert(_make_scored_ip(ip="10.0.0.1", expires_at=past))
        db.upsert(_make_scored_ip(ip="10.0.0.2", expires_at=future))

        active = db.get_active(now)
        assert len(active) == 1
        assert active[0]["ip"] == "10.0.0.2"

    def test_delete_removes_row(self, db: ThreatIntelDB):
        db.upsert(_make_scored_ip(ip="5.5.5.5"))
        assert db.get_by_ip("5.5.5.5") is not None

        db.delete("5.5.5.5")
        assert db.get_by_ip("5.5.5.5") is None

    def test_set_enforced_updates_flag(self, db: ThreatIntelDB):
        db.upsert(_make_scored_ip(ip="3.3.3.3"))
        assert db.get_by_ip("3.3.3.3")["enforced"] == 0

        db.set_enforced("3.3.3.3", True)
        assert db.get_by_ip("3.3.3.3")["enforced"] == 1

        db.set_enforced("3.3.3.3", False)
        assert db.get_by_ip("3.3.3.3")["enforced"] == 0

    def test_idempotent_double_upsert_one_row(self, db: ThreatIntelDB):
        rec = _make_scored_ip(ip="4.4.4.4", score=90.0)
        db.upsert(rec)
        db.upsert(rec)

        all_rows = db.get_all()
        assert len([r for r in all_rows if r["ip"] == "4.4.4.4"]) == 1

    def test_sources_json_roundtrip(self, db: ThreatIntelDB):
        sources = ["abuseipdb", "otx", "spamhaus"]
        db.upsert(_make_scored_ip(ip="6.6.6.6", sources=sources))

        row = db.get_by_ip("6.6.6.6")
        assert row["sources"] == sources
        assert isinstance(row["sources"], list)
