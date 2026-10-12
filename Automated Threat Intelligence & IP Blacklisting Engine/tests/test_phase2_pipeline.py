"""
tests/test_phase2_pipeline.py — Integration tests for Phase 2 pipeline execution
"""
from datetime import datetime, timezone
import pytest

from config import load_config
from main import run_pipeline
from models import RawIndicator
from storage.db import ThreatIntelDB


@pytest.fixture
def test_cfg(tmp_path):
    cfg = load_config()
    # Use a temporary SQLite database
    db_file = str(tmp_path / "test_threat_intel.db")
    cfg["storage"]["db_path"] = db_file
    cfg["policy"]["confidence_threshold"] = 75
    cfg["policy"]["multi_source_bonus"] = 10.0
    return cfg


def test_pipeline_multi_source_corroboration(test_cfg):
    now = datetime.now(timezone.utc)
    indicators = [
        RawIndicator(
            ip="203.0.113.5",
            source="abuseipdb",
            source_confidence=80.0,
            category="brute-force",
            last_reported=now,
        ),
        RawIndicator(
            ip="203.0.113.5",
            source="otx",
            source_confidence=70.0,
            category="brute-force",
            last_reported=now,
        ),
    ]

    decisions = run_pipeline(test_cfg, indicators=indicators)
    assert len(decisions) == 1
    d = decisions[0]
    assert d.scored_ip.ip == "203.0.113.5"
    assert d.action == "block"
    # Weighted avg of 80 (wt 1.0) and 70 (wt 0.8) = 136 / 1.8 = 75.56 + 10 = 85.56
    assert d.scored_ip.combined_score == 85.56
    assert set(d.scored_ip.sources) == {"abuseipdb", "otx"}

    # Verify persisted in SQLite
    db = ThreatIntelDB(test_cfg["storage"]["db_path"])
    row = db.get_by_ip("203.0.113.5")
    assert row is not None
    assert row["combined_score"] == 85.56
    assert row["sources"] == ["abuseipdb", "otx"]
    db.close()


def test_pipeline_low_confidence_is_log_only(test_cfg):
    now = datetime.now(timezone.utc)
    indicators = [
        RawIndicator(
            ip="198.51.100.2",
            source="otx",
            source_confidence=50.0,
            category="scanning",
            last_reported=now,
        )
    ]

    decisions = run_pipeline(test_cfg, indicators=indicators)
    assert len(decisions) == 1
    d = decisions[0]
    assert d.action == "log_only"
    assert d.scored_ip.combined_score == 50.0

    # Ensure NOT persisted in block DB
    db = ThreatIntelDB(test_cfg["storage"]["db_path"])
    row = db.get_by_ip("198.51.100.2")
    assert row is None
    db.close()


def test_pipeline_idempotence(test_cfg):
    now = datetime.now(timezone.utc)
    indicators = [
        RawIndicator(
            ip="192.0.2.1",
            source="abuseipdb",
            source_confidence=90.0,
            category="malware",
            last_reported=now,
        )
    ]

    # Run once
    run_pipeline(test_cfg, indicators=indicators)
    db = ThreatIntelDB(test_cfg["storage"]["db_path"])
    first_seen_1 = db.get_by_ip("192.0.2.1")["first_seen"]
    all_rows_1 = len(db.get_all())
    db.close()

    # Run again with same indicators
    run_pipeline(test_cfg, indicators=indicators)
    db = ThreatIntelDB(test_cfg["storage"]["db_path"])
    first_seen_2 = db.get_by_ip("192.0.2.1")["first_seen"]
    all_rows_2 = len(db.get_all())
    db.close()

    assert all_rows_1 == all_rows_2 == 1
    assert first_seen_1 == first_seen_2
