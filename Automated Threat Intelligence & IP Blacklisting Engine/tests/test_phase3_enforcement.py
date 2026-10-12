"""
tests/test_phase3_enforcement.py — Tests for Phase 3 Enforcement Adapters
========================================================================
Covers:
  - LocalFirewallAdapter (primary, ipset-based)
  - AWSWAFAdapter (optional, boto3-based, cost warning)
  - _run_enforcement() diff and state tracking logic
"""
from __future__ import annotations

import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from enforcement.base_adapter import EnforcerError
from enforcement.aws_waf import AWSWAFAdapter
from enforcement.local_firewall import LocalFirewallAdapter
from main import _run_enforcement
from models import ScoredIP
from storage.db import ThreatIntelDB


# ─────────────────────────────────────────────────────────────────
# 1. LocalFirewallAdapter Tests
# ─────────────────────────────────────────────────────────────────

class TestLocalFirewallAdapter:
    def test_dry_run_add_logs_no_subprocess(self, monkeypatch):
        called = []
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": True})
        res = adapter.add(["1.2.3.4"])
        assert res == 1
        assert len(called) == 0

    def test_dry_run_remove_logs_no_subprocess(self, monkeypatch):
        called = []
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": True})
        res = adapter.remove(["1.2.3.4"])
        assert res == 1
        assert len(called) == 0

    def test_add_calls_ipset_add_with_correct_args(self, monkeypatch):
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)
        adapter = LocalFirewallAdapter({
            "enabled": True,
            "dry_run": False,
            "ipset_name": "my-set",
        })
        adapter.add(["1.2.3.4"])
        assert ["ipset", "add", "my-set", "1.2.3.4"] in calls

    def test_add_returns_count_of_ips(self, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
        )
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": False})
        assert adapter.add(["1.1.1.1", "2.2.2.2"]) == 2

    def test_remove_calls_ipset_del(self, monkeypatch):
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)
        adapter = LocalFirewallAdapter({
            "enabled": True,
            "dry_run": False,
            "ipset_name": "my-set",
        })
        adapter.remove(["1.2.3.4"])
        assert ["ipset", "del", "my-set", "1.2.3.4"] in calls

    def test_ensure_set_exists_calls_create(self, monkeypatch):
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)
        adapter = LocalFirewallAdapter({
            "enabled": True,
            "dry_run": False,
            "ipset_name": "my-set",
            "ipset_type": "hash:net",
        })
        adapter.ensure_set_exists()
        assert ["ipset", "create", "my-set", "hash:net", "-exist"] in calls

    def test_current_set_parses_members_section(self, monkeypatch):
        stdout_data = (
            "Name: threat-intel-blocklist\n"
            "Type: hash:net\n"
            "Header: family inet hashsize 1024 maxelem 65536\n"
            "Size in memory: 544\n"
            "References: 1\n"
            "Number of entries: 2\n"
            "Members:\n"
            "1.2.3.4\n"
            "10.0.0.0/8\n"
        )
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout=stdout_data),
        )
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": False})
        members = adapter.current_set()
        assert members == {"1.2.3.4", "10.0.0.0/8"}

    def test_current_set_returns_empty_in_dry_run(self, monkeypatch):
        called = []
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": True})
        assert adapter.current_set() == set()
        assert len(called) == 0

    def test_subprocess_error_raises_enforcer_error(self, monkeypatch):
        def mock_error(*a, **kw):
            raise subprocess.CalledProcessError(1, ["ipset"], stderr="ipset not found")

        monkeypatch.setattr(subprocess, "run", mock_error)
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": False})
        with pytest.raises(EnforcerError, match="ipset command failed"):
            adapter.ensure_set_exists()

    def test_is_enabled_reads_cfg(self):
        assert LocalFirewallAdapter({"enabled": True}).is_enabled() is True
        assert LocalFirewallAdapter({"enabled": False}).is_enabled() is False
        assert LocalFirewallAdapter({}).is_enabled() is False

    def test_is_dry_run_reads_cfg(self):
        assert LocalFirewallAdapter({"dry_run": True}).is_dry_run() is True
        assert LocalFirewallAdapter({"dry_run": False}).is_dry_run() is False
        assert LocalFirewallAdapter({}).is_dry_run() is False

    def test_add_empty_list_returns_zero(self, monkeypatch):
        called = []
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": False})
        assert adapter.add([]) == 0
        assert len(called) == 0

    def test_remove_empty_list_returns_zero(self, monkeypatch):
        called = []
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))
        adapter = LocalFirewallAdapter({"enabled": True, "dry_run": False})
        assert adapter.remove([]) == 0
        assert len(called) == 0


# ─────────────────────────────────────────────────────────────────
# 2. AWSWAFAdapter Tests
# ─────────────────────────────────────────────────────────────────

class TestAWSWAFAdapter:
    def test_cost_warning_emitted_on_init(self, caplog):
        with caplog.at_level(logging.WARNING):
            AWSWAFAdapter({"enabled": True})
        assert any(
            "cost" in r.message.lower() and "aws waf" in r.message.lower()
            for r in caplog.records
        )

    def test_add_normalizes_ip_to_cidr32(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.get_ip_set.return_value = {
            "LockToken": "tok123",
            "IPSet": {"Addresses": []},
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        monkeypatch.setitem(sys.modules, "boto3", mock_boto3)

        adapter = AWSWAFAdapter({"enabled": True, "dry_run": False, "ip_set_id": "test-id"})
        adapter.add(["1.2.3.4"])

        mock_client.update_ip_set.assert_called_once()
        call_kwargs = mock_client.update_ip_set.call_args[1]
        assert "1.2.3.4/32" in call_kwargs["Addresses"]

    def test_add_preserves_existing_cidr(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.get_ip_set.return_value = {
            "LockToken": "tok123",
            "IPSet": {"Addresses": []},
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        monkeypatch.setitem(sys.modules, "boto3", mock_boto3)

        adapter = AWSWAFAdapter({"enabled": True, "dry_run": False, "ip_set_id": "test-id"})
        adapter.add(["10.0.0.0/8"])

        mock_client.update_ip_set.assert_called_once()
        call_kwargs = mock_client.update_ip_set.call_args[1]
        assert "10.0.0.0/8" in call_kwargs["Addresses"]

    def test_boto3_not_installed_raises(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "boto3", None)
        adapter = AWSWAFAdapter({"enabled": True, "dry_run": False, "ip_set_id": "test-id"})
        with pytest.raises(EnforcerError, match="boto3 not installed"):
            adapter.add(["1.2.3.4"])

    def test_empty_ip_set_id_raises(self, monkeypatch):
        mock_boto3 = MagicMock()
        monkeypatch.setitem(sys.modules, "boto3", mock_boto3)
        adapter = AWSWAFAdapter({"enabled": True, "dry_run": False, "ip_set_id": ""})
        with pytest.raises(EnforcerError, match="ip_set_id must be configured"):
            adapter.add(["1.2.3.4"])

    def test_add_calls_update_ip_set(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.get_ip_set.return_value = {
            "LockToken": "tok456",
            "IPSet": {"Addresses": ["9.9.9.9/32"]},
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        monkeypatch.setitem(sys.modules, "boto3", mock_boto3)

        adapter = AWSWAFAdapter({"enabled": True, "dry_run": False, "ip_set_id": "test-id"})
        res = adapter.add(["1.2.3.4"])
        assert res == 1
        assert mock_client.update_ip_set.call_count == 1

    def test_remove_calls_update_ip_set(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.get_ip_set.return_value = {
            "LockToken": "tok789",
            "IPSet": {"Addresses": ["1.2.3.4/32", "5.6.7.8/32"]},
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        monkeypatch.setitem(sys.modules, "boto3", mock_boto3)

        adapter = AWSWAFAdapter({"enabled": True, "dry_run": False, "ip_set_id": "waf-id"})
        removed = adapter.remove(["1.2.3.4"])
        assert removed == 1
        call_kwargs = mock_client.update_ip_set.call_args[1]
        assert call_kwargs["Addresses"] == ["5.6.7.8/32"]

    def test_is_enabled_false_by_default(self):
        adapter = AWSWAFAdapter({})
        assert adapter.is_enabled() is False

    def test_current_set_dry_run_returns_empty(self):
        adapter = AWSWAFAdapter({"enabled": True, "dry_run": True})
        assert adapter.current_set() == set()

    def test_current_set_calls_get_ip_set(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": ["1.2.3.4/32", "10.0.0.0/8"]},
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        monkeypatch.setitem(sys.modules, "boto3", mock_boto3)

        adapter = AWSWAFAdapter({"enabled": True, "dry_run": False, "ip_set_id": "waf-id"})
        assert adapter.current_set() == {"1.2.3.4/32", "10.0.0.0/8"}

    def test_local_fw_takes_priority_over_waf(self, monkeypatch):
        cfg = {
            "enforcement": {
                "local_firewall": {"enabled": True, "dry_run": True},
                "aws_waf": {"enabled": True, "dry_run": False, "ip_set_id": "waf-id"},
            }
        }
        db = ThreatIntelDB(":memory:")
        db.init_schema()

        waf_inits = []
        orig_waf_init = AWSWAFAdapter.__init__

        def mock_waf_init(self, *a, **kw):
            waf_inits.append(self)
            return orig_waf_init(self, *a, **kw)

        monkeypatch.setattr(AWSWAFAdapter, "__init__", mock_waf_init)

        _run_enforcement(cfg, db)
        assert len(waf_inits) == 0


# ─────────────────────────────────────────────────────────────────
# 3. _run_enforcement() Integration Tests
# ─────────────────────────────────────────────────────────────────

class TestEnforcementIntegration:
    def test_adds_unenforced_ips(self, monkeypatch):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        scored = ScoredIP(
            ip="1.2.3.4",
            combined_score=85.0,
            sources=["abuseipdb"],
            category="brute_force",
            first_seen=now,
            expires_at=now + timedelta(days=1),
        )
        db.upsert(scored)

        mock_add_ips = []
        monkeypatch.setattr(
            LocalFirewallAdapter,
            "add",
            lambda self, ips: mock_add_ips.extend(ips) or len(ips),
        )
        monkeypatch.setattr(LocalFirewallAdapter, "ensure_set_exists", lambda self: None)

        cfg = {"enforcement": {"local_firewall": {"enabled": True, "dry_run": True}}}
        res = _run_enforcement(cfg, db)
        assert "1.2.3.4" in mock_add_ips
        assert res.added == 1

    def test_skips_already_enforced_ips(self, monkeypatch):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        scored = ScoredIP(
            ip="1.2.3.4",
            combined_score=85.0,
            sources=["abuseipdb"],
            category="brute_force",
            first_seen=now,
            expires_at=now + timedelta(days=1),
        )
        db.upsert(scored)
        db.set_enforced("1.2.3.4", True)

        mock_add_ips = []
        monkeypatch.setattr(
            LocalFirewallAdapter,
            "add",
            lambda self, ips: mock_add_ips.extend(ips) or len(ips),
        )

        cfg = {"enforcement": {"local_firewall": {"enabled": True, "dry_run": True}}}
        res = _run_enforcement(cfg, db)
        assert len(mock_add_ips) == 0
        assert res.skipped == 1
        assert res.added == 0

    def test_removes_orphan_ips(self, monkeypatch):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        scored = ScoredIP(
            ip="1.2.3.4",
            combined_score=85.0,
            sources=["abuseipdb"],
            category="brute_force",
            first_seen=now,
            expires_at=now + timedelta(days=1),
        )
        db.upsert(scored)
        db.set_enforced("1.2.3.4", True)

        monkeypatch.setattr(LocalFirewallAdapter, "current_set", lambda self: {"1.2.3.4", "5.6.7.8"})
        removed_ips = []
        monkeypatch.setattr(
            LocalFirewallAdapter,
            "remove",
            lambda self, ips: removed_ips.extend(ips) or len(ips),
        )
        monkeypatch.setattr(LocalFirewallAdapter, "ensure_set_exists", lambda self: None)

        cfg = {"enforcement": {"local_firewall": {"enabled": True, "dry_run": False}}}
        res = _run_enforcement(cfg, db)
        assert "5.6.7.8" in removed_ips
        assert res.removed == 1

    def test_dry_run_does_not_flip_enforced(self, monkeypatch):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        scored = ScoredIP(
            ip="1.2.3.4",
            combined_score=85.0,
            sources=["abuseipdb"],
            category="brute_force",
            first_seen=now,
            expires_at=now + timedelta(days=1),
        )
        db.upsert(scored)

        monkeypatch.setattr(LocalFirewallAdapter, "ensure_set_exists", lambda self: None)
        cfg = {"enforcement": {"local_firewall": {"enabled": True, "dry_run": True}}}
        res = _run_enforcement(cfg, db)
        row = db.get_by_ip("1.2.3.4")
        assert row["enforced"] == 0
        assert res.added == 1

    def test_live_run_flips_enforced_to_one(self, monkeypatch):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        db.upsert(ScoredIP("1.2.3.4", 85.0, ["abuseipdb"], "brute_force", now, now + timedelta(days=1)))
        monkeypatch.setattr(LocalFirewallAdapter, "ensure_set_exists", lambda self: None)
        monkeypatch.setattr(LocalFirewallAdapter, "current_set", lambda self: set())
        monkeypatch.setattr(LocalFirewallAdapter, "add", lambda self, ips: len(ips))

        cfg = {"enforcement": {"local_firewall": {"enabled": True, "dry_run": False}}}
        _run_enforcement(cfg, db)
        row = db.get_by_ip("1.2.3.4")
        assert row["enforced"] == 1

    def test_returns_correct_counts(self, monkeypatch):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        now = datetime.now(timezone.utc)
        # IP 1: unenforced
        db.upsert(ScoredIP("1.1.1.1", 80.0, ["abuseipdb"], "spam", now, now + timedelta(days=1)))
        # IP 2: enforced
        db.upsert(ScoredIP("2.2.2.2", 80.0, ["abuseipdb"], "spam", now, now + timedelta(days=1)))
        db.set_enforced("2.2.2.2", True)

        monkeypatch.setattr(LocalFirewallAdapter, "ensure_set_exists", lambda self: None)
        monkeypatch.setattr(LocalFirewallAdapter, "current_set", lambda self: {"2.2.2.2", "9.9.9.9"})
        monkeypatch.setattr(LocalFirewallAdapter, "add", lambda self, ips: len(ips))
        monkeypatch.setattr(LocalFirewallAdapter, "remove", lambda self, ips: len(ips))

        cfg = {"enforcement": {"local_firewall": {"enabled": True, "dry_run": False}}}
        res = _run_enforcement(cfg, db)
        assert res.added == 1
        assert res.skipped == 1
        assert res.removed == 1
        assert len(res.errors) == 0

    def test_no_adapter_enabled_returns_zero_result(self):
        db = ThreatIntelDB(":memory:")
        db.init_schema()
        cfg = {"enforcement": {}}
        res = _run_enforcement(cfg, db)
        assert res.added == 0
        assert res.removed == 0
        assert res.skipped == 0
        assert len(res.errors) == 0
