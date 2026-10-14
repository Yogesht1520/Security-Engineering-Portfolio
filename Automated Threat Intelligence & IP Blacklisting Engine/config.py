"""
config.py — central configuration loader
=========================================
Load order (highest priority wins):
  1. Environment variables  (TIBL_<SECTION>__<KEY> pattern, e.g. TIBL_API_KEYS__ABUSEIPDB)
  2. config.yaml            (git-ignored; copy from config.yaml.example)
  3. Built-in defaults      (defined in _DEFAULTS below)

Never import real secrets directly — always call get_config().
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Path searched for config.yaml (relative to this file, or set TIBL_CONFIG_PATH)
_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

# Minimal built-in defaults so the skeleton runs even without a config file
_DEFAULTS: dict[str, Any] = {
    "api_keys": {
        "abuseipdb": None,
        "otx": None,
    },
    "sources": {
        "abuseipdb": {"enabled": False, "max_age_days": 30, "min_confidence": 50, "limit": 500, "weight": 1.0},
        "otx":       {"enabled": False, "pulse_limit": 20, "weight": 0.8},
        "spamhaus":  {"enabled": True,  "weight": 0.6},
    },
    "policy": {
        "confidence_threshold": 60,
        "ttl_days": 30,
        "multi_source_bonus": 10,
    },
    "enforcement": {
        "local_firewall": {
            "enabled": True,
            "ipset_name": "threat-intel-blocklist",
            "ipset_type": "hash:net",
            "dry_run": True,          # safe default — no kernel changes until explicitly opted-in
        },
        "aws_waf": {
            "enabled": False,         # always off by default; see COST NOTICE in config.yaml.example
        },
    },
    "storage": {"db_path": "data/threat_intel.db"},
    "audit":   {"log_path": "data/run_history.jsonl"},
    "siem": {
        "enabled": False,
        "mode": "file",
        "format": "json",
        "file_path": "data/siem_events.jsonl",
        "syslog_host": "127.0.0.1",
        "syslog_port": 514,
    },
    "dashboard": {"host": "127.0.0.1", "port": 5000, "chart_days": 30},
    "logging": {"level": "INFO", "format": "%(asctime)s [%(levelname)s] %(name)s — %(message)s"},
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _apply_env_overrides(cfg: dict) -> dict:
    """
    Override config values with TIBL_* environment variables.

    Naming convention:
        TIBL_<SECTION>__<KEY>   → cfg[section][key]
    Examples:
        TIBL_API_KEYS__ABUSEIPDB  → cfg["api_keys"]["abuseipdb"]
        TIBL_POLICY__CONFIDENCE_THRESHOLD → cfg["policy"]["confidence_threshold"]
    """
    prefix = "TIBL_"
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        remainder = env_key[len(prefix):]
        parts = remainder.lower().split("__", maxsplit=1)
        if len(parts) != 2:
            continue
        section, key = parts
        section = section.replace("_", "_")  # no-op, kept for clarity
        if section in cfg and isinstance(cfg[section], dict):
            # Attempt type coercion matching existing value type
            existing = cfg[section].get(key)
            if isinstance(existing, bool):
                cfg[section][key] = env_val.lower() in ("1", "true", "yes")
            elif isinstance(existing, int):
                cfg[section][key] = int(env_val)
            elif isinstance(existing, float):
                cfg[section][key] = float(env_val)
            else:
                cfg[section][key] = env_val
    return cfg


def load_config(config_path: Path | None = None) -> dict:
    """Load and return the merged configuration dict."""
    path = Path(os.environ.get("TIBL_CONFIG_PATH", config_path or _DEFAULT_CONFIG_PATH))

    cfg = dict(_DEFAULTS)  # start with defaults

    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            file_cfg = yaml.safe_load(fh) or {}
        cfg = _deep_merge(cfg, file_cfg)
        logger.debug("Config loaded from %s", path)
    else:
        logger.warning(
            "config.yaml not found at %s — using built-in defaults. "
            "Copy config.yaml.example to config.yaml and fill in your keys.",
            path,
        )

    cfg = _apply_env_overrides(cfg)
    return cfg


# Module-level singleton — call get_config() everywhere instead of load_config()
_config: dict | None = None


def get_config(reload: bool = False) -> dict:
    """Return the cached config, loading it on first call (or if reload=True)."""
    global _config
    if _config is None or reload:
        _config = load_config()
    return _config
