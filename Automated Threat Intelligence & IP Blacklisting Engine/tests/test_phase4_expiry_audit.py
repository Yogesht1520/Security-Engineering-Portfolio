"""
tests/test_phase4_expiry_audit.py — Tests for Phase 4 TTL Expiry Sweep & Audit Logging
======================================================================================
Covers:
  - sweep_expired() logic (db deletion, adapter removal, dry-run safety)
  - AuditLogger (JSONL append, parsing, error resilience, recent run queries)
  - Full pipeline integration and the official acceptance scenario
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from audit.logger import AuditLogger
from engine.expiry import ExpiryResult, sweep_expired
from enforcement.base_adapter import BaseEnforcer, EnforcerError
from main import run_pipeline
from models import RawIndicator, ScoredIP
from storage.db import ThreatIntelDB


class DummyEnforcer(BaseEnforcer):
    """Test stub for BaseEnforcer."""

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__({"enabled": True, "dry_run": dry_run})
        self.removed_ips: list[str] = []
        self.added_ips: list[str] = []

    def add(self, ips: list[str]) -> int:
        self.added_ips.extend(ips)
        return len(ips)

    def remove(self, ips: list[str]) -> int:
        self.removed_ips.extend(ips)
        return len(ips)

    def current_set(self) -> set[str]:
        return set(self.added_ips)


# ─────────────────────────────────────────────────────────────────
# 1. TTL Expiry Sweeper Tests
# ─────────────────────────────────────────────────────────────────

class TestExpirySweeper:
    def test_sweep_expired_deletes_from_db(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        past = datetime.now(timezone.utc) - timedelta(days=5)
        db.upsert(ScoredIP("1.1.1.1", 85.0, ["abuseipdb"], "spam", past - timedelta(days=30), past))

        res = sweep_expired(db)
        assert res.expired_count == 1
        assert "1.1.1.1" in [r["ip"] for r in res.expired_records]
        assert db.get_by_ip("1.1.1.1") is None

    def test_sweep_expired_calls_adapter_remove_when_enforced(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        past = datetime.now(timezone.utc) - timedelta(days=2)
        db.upsert(ScoredIP("1.1.1.1", 85.0, ["abuseipdb"], "spam", past - timedelta(days=30), past))
        db.set_enforced("1.1.1.1", True)

        adapter = DummyEnforcer(dry_run=False)
        res = sweep_expired(db, adapter=adapter)

        assert "1.1.1.1" in res.removed_from_enforcer
        assert "1.1.1.1" in adapter.removed_ips
        assert db.get_by_ip("1.1.1.1") is None

    def test_sweep_expired_skips_adapter_remove_when_not_enforced(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        past = datetime.now(timezone.utc) - timedelta(days=2)
        db.upsert(ScoredIP("1.1.1.1", 85.0, ["abuseipdb"], "spam", past - timedelta(days=30), past))
        # Notice enforced is 0 by default

        adapter = DummyEnforcer(dry_run=False)
        res = sweep_expired(db, adapter=adapter)

        assert len(res.removed_from_enforcer) == 0
        assert len(adapter.removed_ips) == 0
        assert db.get_by_ip("1.1.1.1") is None

    def test_sweep_ignores_active_unexpired_rows(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        # Expired
        db.upsert(ScoredIP("1.1.1.1", 85.0, ["abuseipdb"], "spam", now - timedelta(days=35), now - timedelta(days=5)))
        # Active
        db.upsert(ScoredIP("2.2.2.2", 90.0, ["abuseipdb"], "c2", now - timedelta(days=1), now + timedelta(days=29)))

        res = sweep_expired(db)
        assert res.expired_count == 1
        assert db.get_by_ip("1.1.1.1") is None
        assert db.get_by_ip("2.2.2.2") is not None

    def test_sweep_dry_run_preserves_db(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        past = datetime.now(timezone.utc) - timedelta(days=2)
        db.upsert(ScoredIP("1.1.1.1", 85.0, ["abuseipdb"], "spam", past - timedelta(days=30), past))
        db.set_enforced("1.1.1.1", True)

        adapter = DummyEnforcer(dry_run=True)
        res = sweep_expired(db, adapter=adapter, dry_run=True)

        assert res.expired_count == 1
        assert "1.1.1.1" in res.removed_from_enforcer
        # Row must STILL be in the database in dry run!
        assert db.get_by_ip("1.1.1.1") is not None
        assert len(adapter.removed_ips) == 0

    def test_sweep_empty_db(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        res = sweep_expired(db)
        assert res.expired_count == 0
        assert len(res.expired_records) == 0
        assert len(res.removed_from_enforcer) == 0
        assert len(res.errors) == 0

    def test_sweep_handles_adapter_error(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        past = datetime.now(timezone.utc) - timedelta(days=1)
        db.upsert(ScoredIP("1.1.1.1", 85.0, ["abuseipdb"], "spam", past - timedelta(days=30), past))
        db.set_enforced("1.1.1.1", True)

        failing_adapter = DummyEnforcer(dry_run=False)

        def raise_err(ips):
            raise EnforcerError("Kernel communication failure")

        failing_adapter.remove = raise_err

        res = sweep_expired(db, adapter=failing_adapter)
        assert len(res.errors) == 1
        assert "Kernel communication failure" in res.errors[0]
        # DB deletion still succeeds
        assert db.get_by_ip("1.1.1.1") is None

    def test_sweep_backdated_acceptance(self):
        """Official acceptance scenario: manually backdate expires_at, run sweep, confirm removal."""
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        # 1. Insert entry that was previously added and enforced
        db.upsert(ScoredIP("198.51.100.42", 88.0, ["otx", "abuseipdb"], "botnet", now - timedelta(days=31), now - timedelta(seconds=10)))
        db.set_enforced("198.51.100.42", True)

        adapter = DummyEnforcer(dry_run=False)
        adapter.added_ips.append("198.51.100.42")

        # 2. Run sweep
        result = sweep_expired(db, adapter=adapter, now=now)

        # 3. Verify removal
        assert result.expired_count == 1
        assert "198.51.100.42" in result.removed_from_enforcer
        assert "198.51.100.42" in adapter.removed_ips
        assert db.get_by_ip("198.51.100.42") is None


# ─────────────────────────────────────────────────────────────────
# 2. AuditLogger Tests
# ─────────────────────────────────────────────────────────────────

class TestAuditLogger:
    def test_audit_logger_creates_file_and_dir(self, tmp_path):
        log_file = tmp_path / "nested" / "logs" / "run_history.jsonl"
        logger = AuditLogger(log_file)
        logger.log_run({"run_id": "test-1", "summary": {"blocked": 2}})
        assert log_file.exists()
        assert log_file.is_file()

    def test_audit_logger_appends_valid_json(self, tmp_path):
        log_file = tmp_path / "run_history.jsonl"
        logger = AuditLogger(log_file)
        payload = {
            "run_id": "abc-123",
            "timestamp": "2026-10-12T16:00:00Z",
            "summary": {"blocked": 5, "expired_count": 1},
        }
        logger.log_run(payload)

        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["run_id"] == "abc-123"
        assert parsed["summary"]["blocked"] == 5

    def test_audit_logger_preserves_decisions_and_expirations(self, tmp_path):
        log_file = tmp_path / "run_history.jsonl"
        logger = AuditLogger(log_file)
        payload = {
            "run_id": "run-xyz",
            "decisions": [
                {
                    "ip": "1.2.3.4",
                    "action": "block",
                    "score": 92.5,
                    "sources": ["abuseipdb", "otx"],
                    "reason": "Confidence 92.5 >= threshold 60.0",
                }
            ],
            "expirations": [
                {
                    "ip": "9.9.9.9",
                    "score": 75.0,
                    "sources": ["spamhaus"],
                    "reason": "TTL expired",
                }
            ],
        }
        logger.log_run(payload)

        recent = logger.get_recent_runs(limit=5)
        assert len(recent) == 1
        run = recent[0]
        assert len(run["decisions"]) == 1
        assert run["decisions"][0]["ip"] == "1.2.3.4"
        assert run["decisions"][0]["score"] == 92.5
        assert len(run["expirations"]) == 1
        assert run["expirations"][0]["ip"] == "9.9.9.9"

    def test_audit_logger_get_recent_runs_order(self, tmp_path):
        log_file = tmp_path / "run_history.jsonl"
        logger = AuditLogger(log_file)
        for i in range(5):
            logger.log_run({"run_id": f"run-{i}", "index": i})

        recent = logger.get_recent_runs(limit=3)
        assert len(recent) == 3
        # Should be newest first
        assert recent[0]["index"] == 4
        assert recent[1]["index"] == 3
        assert recent[2]["index"] == 2

    def test_audit_logger_handles_corrupted_lines(self, tmp_path):
        log_file = tmp_path / "run_history.jsonl"
        log_file.write_text('{"run_id": "valid-1"}\nCORRUPT JSON LINE\n{"run_id": "valid-2"}\n', encoding="utf-8")

        logger = AuditLogger(log_file)
        recent = logger.get_recent_runs()
        assert len(recent) == 2
        assert recent[0]["run_id"] == "valid-2"
        assert recent[1]["run_id"] == "valid-1"

    def test_audit_logger_get_total_runs(self, tmp_path):
        log_file = tmp_path / "run_history.jsonl"
        logger = AuditLogger(log_file)
        assert logger.get_total_runs() == 0

        for i in range(4):
            logger.log_run({"run_id": f"run-{i}"})
        assert logger.get_total_runs() == 4


# ─────────────────────────────────────────────────────────────────
# 3. Pipeline Integration Tests
# ─────────────────────────────────────────────────────────────────

class TestPipelinePhase4Integration:
    def test_pipeline_end_to_end_phase4(self, tmp_path):
        db_path = str(tmp_path / "test_intel.db")
        log_path = str(tmp_path / "history.jsonl")

        cfg = {
            "storage": {"db_path": db_path},
            "audit": {"log_path": log_path},
            "policy": {"confidence_threshold": 60, "multi_source_bonus": 10},
            "enforcement": {
                "local_firewall": {"enabled": True, "dry_run": True, "ipset_name": "test-set"},
                "aws_waf": {"enabled": False},
            },
            "sources": {"abuseipdb": {"enabled": False}, "otx": {"enabled": False}, "spamhaus": {"enabled": False}},
        }

        indicators = [
            RawIndicator("203.0.113.10", "abuseipdb", 85.0, "brute_force", datetime.now(timezone.utc)),
            RawIndicator("203.0.113.10", "otx", 90.0, "brute_force", datetime.now(timezone.utc)),
        ]

        decisions = run_pipeline(cfg, indicators=indicators)
        assert len(decisions) == 1
        assert decisions[0].action == "block"

        # Verify audit log was created and contains the block decision
        audit_logger = AuditLogger(log_path)
        recent = audit_logger.get_recent_runs(limit=1)
        assert len(recent) == 1
        record = recent[0]
        assert record["summary"]["blocked"] == 1
        assert record["summary"]["unique_ips"] == 1
        assert len(record["decisions"]) == 1
        assert record["decisions"][0]["ip"] == "203.0.113.10"
        assert record["decisions"][0]["score"] == 97.5

    def test_pipeline_expiry_acceptance_scenario(self, tmp_path):
        """
        1. Insert an indicator that expired 2 days ago.
        2. Run the pipeline with no new indicators.
        3. Confirm it was swept, deleted from DB, and recorded in the audit log under expirations.
        """
        db_path = str(tmp_path / "test_intel.db")
        log_path = str(tmp_path / "history.jsonl")

        # Pre-populate database with an expired row
        db = ThreatIntelDB(db_path)
        db.init_schema()
        now = datetime.now(timezone.utc)
        past_first_seen = now - timedelta(days=32)
        past_expires_at = now - timedelta(days=2)
        db.upsert(ScoredIP("198.51.100.99", 85.0, ["spamhaus"], "spam", past_first_seen, past_expires_at))
        db.set_enforced("198.51.100.99", True)
        db.close()

        cfg = {
            "storage": {"db_path": db_path},
            "audit": {"log_path": log_path},
            "policy": {"confidence_threshold": 60, "multi_source_bonus": 10},
            "enforcement": {
                # Run with dry_run False, but mocked adapter
                "local_firewall": {"enabled": True, "dry_run": False, "ipset_name": "test-set"},
                "aws_waf": {"enabled": False},
            },
            "sources": {"abuseipdb": {"enabled": False}, "otx": {"enabled": False}, "spamhaus": {"enabled": False}},
        }

        # Mock ipset commands so local firewall doesn't invoke real kernel on host
        from enforcement.local_firewall import LocalFirewallAdapter
        adapter_calls = []

        def mock_run_ipset(self, *args, capture=False):
            adapter_calls.append(args)
            if args[0] == "list":
                return "Members:\n198.51.100.99\n"
            return ""

        import unittest.mock
        with unittest.mock.patch.object(LocalFirewallAdapter, "_run_ipset", mock_run_ipset):
            run_pipeline(cfg, indicators=[])

        # Verify DB: expired record must be deleted
        verify_db = ThreatIntelDB(db_path)
        assert verify_db.get_by_ip("198.51.100.99") is None
        verify_db.close()

        # Verify audit log: record must be present under expirations
        audit_logger = AuditLogger(log_path)
        recent = audit_logger.get_recent_runs(limit=1)
        assert len(recent) == 1
        record = recent[0]
        assert record["summary"]["expired_count"] == 1
        assert len(record["expirations"]) == 1
        assert record["expirations"][0]["ip"] == "198.51.100.99"
        assert record["expirations"][0]["reason"] == "TTL expired"

    def test_audit_logger_empty_file_returns_empty_list(self, tmp_path):
        empty_log = tmp_path / "empty.jsonl"
        empty_log.write_text("", encoding="utf-8")
        logger = AuditLogger(empty_log)
        assert logger.get_recent_runs() == []
        assert logger.get_total_runs() == 0

    def test_pipeline_audit_log_path_from_config(self, tmp_path):
        custom_log = tmp_path / "custom_audit" / "custom_log.jsonl"
        cfg = {
            "storage": {"db_path": str(tmp_path / "db.sqlite")},
            "audit": {"log_path": str(custom_log)},
            "policy": {"confidence_threshold": 60},
            "enforcement": {"local_firewall": {"enabled": False}, "aws_waf": {"enabled": False}},
            "sources": {"abuseipdb": {"enabled": False}, "otx": {"enabled": False}, "spamhaus": {"enabled": False}},
        }
        run_pipeline(cfg, indicators=[])
        assert custom_log.exists()
        assert AuditLogger(custom_log).get_total_runs() == 1

