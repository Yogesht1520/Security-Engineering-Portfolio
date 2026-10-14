"""
tests/test_v1_failsafe_safety.py — Tests for fail-safe state machine, circuit breakers, and rollback
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.expiry import sweep_expired
from engine.failsafe import (
    FeedStatus,
    OperationalState,
    evaluate_pipeline_health,
    should_freeze_ip_expiry,
)
from enforcement.rollback import SnapshotManager
from enforcement.safety import CircuitBreakerError, GuardrailConfig, SafetyController
from models import ScoredIP
from storage.db import ThreatIntelDB


class DummyAdapter:
    def __init__(self, current: set[str] | None = None) -> None:
        self._current = set(current or set())
        self.added_calls: list[list[str]] = []
        self.removed_calls: list[list[str]] = []

    def is_dry_run(self) -> bool:
        return False

    def current_set(self) -> set[str]:
        return set(self._current)

    def add(self, ips: list[str]) -> int:
        self.added_calls.append(ips)
        self._current.update(ips)
        return len(ips)

    def remove(self, ips: list[str]) -> int:
        self.removed_calls.append(ips)
        self._current.difference_update(ips)
        return len(ips)


class TestFailSafeEngine:
    def test_pipeline_operational_state_evaluation(self):
        # 1. All healthy
        all_ok = {
            "abuseipdb": FeedStatus("abuseipdb", healthy=True),
            "otx": FeedStatus("otx", healthy=True),
        }
        res_ok = evaluate_pipeline_health(all_ok, ["abuseipdb", "otx"])
        assert res_ok.operational_state == OperationalState.HEALTHY

        # 2. One feed failed -> DEGRADED
        partial = {
            "abuseipdb": FeedStatus("abuseipdb", healthy=True),
            "otx": FeedStatus("otx", healthy=False, error="HTTP 500"),
        }
        res_deg = evaluate_pipeline_health(partial, ["abuseipdb", "otx"])
        assert res_deg.operational_state == OperationalState.DEGRADED
        assert "otx" in res_deg.failed_sources

        # 3. All feeds failed -> FAIL_SAFE
        all_failed = {
            "abuseipdb": FeedStatus("abuseipdb", healthy=False, error="Timeout"),
            "otx": FeedStatus("otx", healthy=False, error="HTTP 429"),
        }
        res_fs = evaluate_pipeline_health(all_failed, ["abuseipdb", "otx"])
        assert res_fs.operational_state == OperationalState.FAIL_SAFE

    def test_fail_safe_expiry_freezing(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=5)

        with ThreatIntelDB(db_path) as db:
            db.init_schema()
            # IP flagged only by OTX
            ip1 = ScoredIP("198.51.100.1", 80.0, sources=["otx"], expires_at=past)
            # IP flagged by AbuseIPDB
            ip2 = ScoredIP("198.51.100.2", 80.0, sources=["abuseipdb"], expires_at=past)
            db.upsert(ip1)
            db.upsert(ip2)

            adapter = DummyAdapter(current={"198.51.100.1", "198.51.100.2"})

            # OTX is offline in DEGRADED state
            result = sweep_expired(
                db=db,
                adapter=adapter,
                now=now,
                failed_sources={"otx"},
                operational_state=OperationalState.DEGRADED,
            )

            # IP1 (OTX only) must be FROZEN, IP2 (AbuseIPDB healthy) is expired
            assert result.expired_count == 1
            assert len(result.frozen_records) == 1
            assert result.frozen_records[0]["ip"] == "198.51.100.1"

            # DB should still contain the frozen IP
            assert db.get_by_ip("198.51.100.1") is not None
            assert db.get_by_ip("198.51.100.2") is None


class TestSafetyGuardrails:
    def test_circuit_breaker_max_changes(self):
        safety = SafetyController(GuardrailConfig(max_changes_per_run=10))
        # 12 changes planned exceeds max of 10
        with pytest.raises(CircuitBreakerError, match="exceeds max_changes_per_run"):
            safety.verify_rate_of_change(current_active_count=100, to_add_count=6, to_remove_count=6)

        # Force override allows it
        safety.verify_rate_of_change(current_active_count=100, to_add_count=6, to_remove_count=6, force=True)

    def test_circuit_breaker_percentage_limit(self):
        # 20 active IPs; 10 changes = 50% change ratio (limit is 20%)
        safety = SafetyController(GuardrailConfig(max_change_percentage=0.20, min_size_for_percentage_check=20))
        with pytest.raises(CircuitBreakerError, match="Volatility circuit breaker"):
            safety.verify_rate_of_change(current_active_count=20, to_add_count=5, to_remove_count=5)


class TestRollbackAndSnapshots:
    def test_snapshot_creation_and_atomic_rollback(self, tmp_path):
        snap_dir = tmp_path / "snapshots"
        mgr = SnapshotManager(snap_dir)

        # 1. Save LKG snapshot
        target_ips = ["198.51.100.10", "198.51.100.20", "198.51.100.30"]
        snap_path = mgr.save_snapshot("DummyAdapter", target_ips, run_id="run12345")
        assert snap_path.exists()

        # 2. Adapter state has drifted (e.g. unwanted IP added, valid IP missing)
        adapter = DummyAdapter(current={"198.51.100.10", "198.51.100.99"})

        # 3. Rollback
        res = mgr.rollback(adapter=adapter)
        assert res["total_target"] == 3
        # Should add 198.51.100.20, 198.51.100.30 (2 added)
        # Should remove 198.51.100.99 (1 removed)
        assert res["added"] == 2
        assert res["removed"] == 1
        assert adapter.current_set() == set(target_ips)
