"""
tests/test_phase0_config.py — Phase 0: config loader and skeleton smoke tests
==============================================================================
All tests must pass before moving to Phase 1.
Run:  pytest tests/test_phase0_config.py -v
"""
from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

# Make the project root importable regardless of how pytest is invoked
sys.path.insert(0, str(Path(__file__).parent.parent))

import config as config_module
from config import _deep_merge, _apply_env_overrides, load_config, get_config


# ─────────────────────────────────────────────────────────────────
# 1. _deep_merge tests
# ─────────────────────────────────────────────────────────────────

class TestDeepMerge:
    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        override = {"b": 99, "c": 3}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 99, "c": 3}

    def test_nested_merge(self):
        base = {"policy": {"threshold": 60, "ttl": 30}}
        override = {"policy": {"threshold": 80}}
        result = _deep_merge(base, override)
        assert result["policy"]["threshold"] == 80
        assert result["policy"]["ttl"] == 30, "Nested keys not in override must be preserved"

    def test_does_not_mutate_base(self):
        base = {"a": {"x": 1}}
        override = {"a": {"x": 2}}
        _deep_merge(base, override)
        assert base["a"]["x"] == 1, "deep_merge must not mutate the original base dict"

    def test_override_replaces_non_dict_with_dict(self):
        base = {"key": "string"}
        override = {"key": {"nested": True}}
        result = _deep_merge(base, override)
        assert result["key"] == {"nested": True}


# ─────────────────────────────────────────────────────────────────
# 2. Environment variable override tests
# ─────────────────────────────────────────────────────────────────

class TestEnvOverrides:
    def test_string_override(self, monkeypatch):
        monkeypatch.setenv("TIBL_API_KEYS__ABUSEIPDB", "test-key-abc")
        cfg = {"api_keys": {"abuseipdb": None}}
        result = _apply_env_overrides(cfg)
        assert result["api_keys"]["abuseipdb"] == "test-key-abc"

    def test_bool_override_true(self, monkeypatch):
        monkeypatch.setenv("TIBL_ENFORCEMENT__DRY_RUN", "true")
        cfg = {"enforcement": {"dry_run": False}}
        result = _apply_env_overrides(cfg)
        assert result["enforcement"]["dry_run"] is True

    def test_bool_override_false(self, monkeypatch):
        monkeypatch.setenv("TIBL_ENFORCEMENT__DRY_RUN", "0")
        cfg = {"enforcement": {"dry_run": True}}
        result = _apply_env_overrides(cfg)
        assert result["enforcement"]["dry_run"] is False

    def test_int_override(self, monkeypatch):
        monkeypatch.setenv("TIBL_POLICY__TTL_DAYS", "90")
        cfg = {"policy": {"ttl_days": 30}}
        result = _apply_env_overrides(cfg)
        assert result["policy"]["ttl_days"] == 90

    def test_unknown_prefix_ignored(self, monkeypatch):
        monkeypatch.setenv("SOME_OTHER_VAR", "should-be-ignored")
        cfg = {"api_keys": {"abuseipdb": "original"}}
        result = _apply_env_overrides(cfg)
        assert result["api_keys"]["abuseipdb"] == "original"

    def test_unknown_section_ignored(self, monkeypatch):
        monkeypatch.setenv("TIBL_NONEXISTENT__KEY", "value")
        cfg = {"api_keys": {"abuseipdb": "original"}}
        # Should not raise
        result = _apply_env_overrides(cfg)
        assert "nonexistent" not in result


# ─────────────────────────────────────────────────────────────────
# 3. load_config with a temporary config file
# ─────────────────────────────────────────────────────────────────

class TestLoadConfig:
    def test_loads_yaml_file(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            api_keys:
              abuseipdb: "real-key-from-file"
            policy:
              confidence_threshold: 75
        """))
        cfg = load_config(config_path=cfg_file)
        assert cfg["api_keys"]["abuseipdb"] == "real-key-from-file"
        assert cfg["policy"]["confidence_threshold"] == 75

    def test_defaults_applied_when_no_file(self, tmp_path):
        missing = tmp_path / "nonexistent.yaml"
        cfg = load_config(config_path=missing)
        # Defaults must always be present
        assert "policy" in cfg
        assert "enforcement" in cfg
        assert "sources" in cfg

    def test_file_overrides_default_but_keeps_other_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("policy:\n  confidence_threshold: 90\n")
        cfg = load_config(config_path=cfg_file)
        assert cfg["policy"]["confidence_threshold"] == 90
        # TTL default still present
        assert cfg["policy"]["ttl_days"] == 30

    def test_aws_waf_disabled_by_default(self, tmp_path):
        missing = tmp_path / "nonexistent.yaml"
        cfg = load_config(config_path=missing)
        assert cfg["enforcement"]["aws_waf"]["enabled"] is False, (
            "AWS WAF must be disabled by default to avoid unexpected costs"
        )

    def test_local_firewall_dry_run_by_default(self, tmp_path):
        missing = tmp_path / "nonexistent.yaml"
        cfg = load_config(config_path=missing)
        assert cfg["enforcement"]["local_firewall"]["dry_run"] is True, (
            "Local firewall must default to dry_run=True for safety"
        )


# ─────────────────────────────────────────────────────────────────
# 4. get_config singleton tests
# ─────────────────────────────────────────────────────────────────

class TestGetConfig:
    def test_returns_dict(self, monkeypatch):
        # Force reload to avoid leftover state from other tests
        monkeypatch.setattr(config_module, "_config", None)
        cfg = get_config(reload=True)
        assert isinstance(cfg, dict)

    def test_singleton_returns_same_object(self, monkeypatch):
        monkeypatch.setattr(config_module, "_config", None)
        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1 is cfg2, "get_config() must return the same object without reload"

    def test_reload_returns_new_object(self, monkeypatch):
        monkeypatch.setattr(config_module, "_config", None)
        cfg1 = get_config()
        cfg2 = get_config(reload=True)
        # Values same, but could be a fresh dict
        assert cfg1["policy"]["ttl_days"] == cfg2["policy"]["ttl_days"]


# ─────────────────────────────────────────────────────────────────
# 5. Models smoke test
# ─────────────────────────────────────────────────────────────────

class TestModels:
    def test_raw_indicator_instantiation(self):
        from datetime import datetime, timezone
        from models import RawIndicator
        ind = RawIndicator(
            ip="1.2.3.4",
            source="abuseipdb",
            source_confidence=85.0,
            category="brute-force",
            last_reported=datetime.now(timezone.utc),
        )
        assert ind.ip == "1.2.3.4"
        assert 0 <= ind.source_confidence <= 100

    def test_scored_ip_instantiation(self):
        from datetime import datetime, timezone, timedelta
        from models import ScoredIP
        now = datetime.now(timezone.utc)
        scored = ScoredIP(
            ip="5.6.7.8",
            combined_score=72.5,
            sources=["abuseipdb", "otx"],
            category="spam",
            first_seen=now,
            expires_at=now + timedelta(days=30),
        )
        assert scored.combined_score == 72.5
        assert len(scored.sources) == 2


# ─────────────────────────────────────────────────────────────────
# 6. Main pipeline smoke test (no real network calls)
# ─────────────────────────────────────────────────────────────────

class TestMainPipelineSkeleton:
    def test_main_runs_without_error(self, monkeypatch, capsys):
        """main.run_pipeline() must complete without raising."""
        import config as config_module
        monkeypatch.setattr(config_module, "_config", None)
        import main
        cfg = load_config()
        main.run_pipeline(cfg)   # should not raise

    def test_aws_waf_warning_when_enabled(self, monkeypatch, capsys, caplog):
        """A log warning must appear if AWS WAF is accidentally enabled."""
        import logging
        import config as config_module
        monkeypatch.setattr(config_module, "_config", None)
        import main
        cfg = load_config()
        cfg["enforcement"]["aws_waf"]["enabled"] = True
        with caplog.at_level(logging.WARNING, logger="main"):
            main.run_pipeline(cfg)
        assert any("AWS WAF" in record.message and "cost" in record.message.lower()
                   for record in caplog.records), (
            "A cost warning must be emitted when AWS WAF adapter is enabled"
        )
