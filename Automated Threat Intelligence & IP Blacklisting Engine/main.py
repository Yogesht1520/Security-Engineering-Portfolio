"""
main.py — Threat Intelligence IP Blacklisting Engine
======================================================
Orchestrates one full pipeline run:
  collect → deduplicate+score → policy decision → enforce → expire → audit
"""
from __future__ import annotations

import logging
import os
import sys
import uuid
from datetime import datetime, timezone

from audit.logger import AuditLogger
from config import get_config
from engine.dedup import deduplicate
from engine.expiry import sweep_expired
from engine.policy import PolicyDecision, apply_policy
from engine.scoring import compute_score
from enforcement import (
    AWSWAFAdapter,
    BaseEnforcer,
    EnforcementResult,
    LocalFirewallAdapter,
)
from intel.abuseipdb import AbuseIPDBSource
from intel.base_source import BaseIntelSource, SourceFetchError
from intel.otx import OTXSource
from intel.spamhaus import SpamhausSource
from models import RawIndicator
from storage.db import ThreatIntelDB

SOURCE_REGISTRY: dict[str, type[BaseIntelSource]] = {
    "abuseipdb": AbuseIPDBSource,
    "otx": OTXSource,
    "spamhaus": SpamhausSource,
}


def _setup_logging(cfg: dict) -> None:
    log_cfg = cfg.get("logging", {})
    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    fmt = log_cfg.get("format", "%(asctime)s [%(levelname)s] %(name)s — %(message)s")
    logging.basicConfig(level=level, format=fmt, stream=sys.stdout)


def _collect_from_sources(cfg: dict) -> list[RawIndicator]:
    """Collect threat indicators from all enabled sources."""
    logger = logging.getLogger("main.collect")

    # Safety guard: avoid burning external API quotas during automated test runs
    if "PYTEST_CURRENT_TEST" in os.environ and not cfg.get("_allow_live_network", False):
        logger.info("  [test environment] Skipping live network collection during pytest run")
        return []

    indicators: list[RawIndicator] = []
    sources_cfg = cfg.get("sources", {})

    for name, src_cls in SOURCE_REGISTRY.items():
        src_cfg = sources_cfg.get(name, {})
        if not src_cfg.get("enabled", False):
            continue

        try:
            source = src_cls(name, src_cfg)
            fetched = source.fetch()
            logger.info("  [%s] Collected %d indicators", name, len(fetched))
            indicators.extend(fetched)
        except SourceFetchError as exc:
            logger.warning("  [%s] Fetch failed: %s", name, exc)
        except Exception as exc:
            logger.warning("  [%s] Unexpected error during fetch: %s", name, exc)

    return indicators


def _get_enforcement_adapter(
    cfg: dict,
    logger: logging.Logger | None = None,
) -> BaseEnforcer | None:
    """Instantiate the active enforcement adapter based on precedence."""
    if logger is None:
        logger = logging.getLogger("main.enforcement")

    fw_cfg = cfg.get("enforcement", {}).get("local_firewall", {})
    waf_cfg = cfg.get("enforcement", {}).get("aws_waf", {})

    if fw_cfg.get("enabled"):
        dry = " [DRY-RUN]" if fw_cfg.get("dry_run") else ""
        logger.info("  LocalFirewall%s — ipset name: %s", dry, fw_cfg.get("ipset_name"))
        return LocalFirewallAdapter(fw_cfg)
    elif waf_cfg.get("enabled"):
        return AWSWAFAdapter(waf_cfg)
    else:
        logger.warning("[Phase 3] No enforcement adapter enabled — skipping")
        return None


def _run_enforcement(
    cfg: dict,
    db: ThreatIntelDB,
    decisions: list[PolicyDecision] | None = None,
    logger: logging.Logger | None = None,
    adapter: BaseEnforcer | None = None,
) -> EnforcementResult:
    """
    Execute Phase 3 enforcement.
    LocalFirewallAdapter takes priority over AWSWAFAdapter.
    Diffs DB active indicators against enforcement target.
    """
    if logger is None:
        logger = logging.getLogger("main.enforcement")

    if adapter is None:
        adapter = _get_enforcement_adapter(cfg, logger)

    if adapter is None:
        return EnforcementResult(0, 0, 0)

    active_records = db.get_active()
    active_ip_set = {r["ip"] for r in active_records}

    # Ensure target set exists if supported
    if hasattr(adapter, "ensure_set_exists"):
        try:
            adapter.ensure_set_exists()
        except Exception as exc:
            logger.error("Failed to ensure target set exists: %s", exc)
            return EnforcementResult(0, 0, 0, errors=[str(exc)])

    # Compute to_add: active records where enforced == 0
    to_add = [r["ip"] for r in active_records if not r.get("enforced")]
    skipped = len(active_records) - len(to_add)

    # Compute to_remove: orphans in current set not in active_ip_set
    to_remove: list[str] = []
    try:
        current = adapter.current_set()
        to_remove = [ip for ip in current if ip not in active_ip_set]
    except Exception as exc:
        logger.warning("Failed to fetch current enforcement set: %s", exc)

    added_count = 0
    removed_count = 0
    errors: list[str] = []

    # Add unenforced IPs
    if to_add:
        try:
            added_count = adapter.add(to_add)
            if not adapter.is_dry_run():
                for ip in to_add:
                    db.set_enforced(ip, True)
        except Exception as exc:
            err_msg = f"Add failed: {exc}"
            logger.error(err_msg)
            errors.append(err_msg)

    # Remove orphan IPs
    if to_remove:
        try:
            removed_count = adapter.remove(to_remove)
            if not adapter.is_dry_run():
                for ip in to_remove:
                    db.set_enforced(ip, False)
        except Exception as exc:
            err_msg = f"Remove failed: {exc}"
            logger.error(err_msg)
            errors.append(err_msg)

    return EnforcementResult(
        added=added_count,
        removed=removed_count,
        skipped=skipped,
        errors=errors,
    )


def run_pipeline(
    cfg: dict,
    indicators: list[RawIndicator] | None = None,
) -> list[PolicyDecision]:
    """
    Execute the threat intelligence pipeline.

    Args:
        cfg: The application configuration dictionary.
        indicators: Optional pre-collected indicators (skips live fetch if provided).

    Returns:
        List of PolicyDecision objects resulting from this run.
    """
    logger = logging.getLogger("main")
    run_start = datetime.now(timezone.utc)
    logger.info("═" * 60)
    logger.info("Threat Intelligence Blacklisting Engine — run started")
    logger.info("Run timestamp (UTC): %s", run_start.isoformat())
    logger.info("═" * 60)

    # ── Phase 1: Collect from intel sources ───────────────────────────────────
    logger.info("[Phase 1] Collecting threat indicators from enabled sources …")
    enabled_sources = [
        name for name, src_cfg in cfg.get("sources", {}).items()
        if src_cfg.get("enabled", False)
    ]
    if enabled_sources:
        logger.info("  Sources enabled: %s", ", ".join(enabled_sources))
    else:
        logger.warning("  No intel sources enabled — check config.yaml")

    if indicators is not None:
        raw_indicators = indicators
        logger.info("  Using provided raw_indicators: %d", len(raw_indicators))
    else:
        raw_indicators = _collect_from_sources(cfg)
        logger.info("  Total raw_indicators collected: %d", len(raw_indicators))

    # ── Phase 2: Dedup + score + store ────────────────────────────────────────
    logger.info("[Phase 2] Deduplicating and scoring indicators …")
    buckets = deduplicate(raw_indicators)
    logger.info("  Unique IP targets after dedup: %d", len(buckets))

    db_path = cfg.get("storage", {}).get("db_path", "data/threat_intel.db")
    with ThreatIntelDB(db_path) as db:
        db.init_schema()

        source_weights = {
            name: src.get("weight", 1.0)
            for name, src in cfg.get("sources", {}).items()
        }
        multi_source_bonus = cfg.get("policy", {}).get("multi_source_bonus", 10.0)
        policy_cfg = cfg.get("policy", {})

        decisions: list[PolicyDecision] = []
        for ip, bucket in buckets.items():
            score = compute_score(bucket, source_weights, multi_source_bonus)
            existing = db.get_by_ip(ip)
            decision = apply_policy(ip, bucket, score, policy_cfg, existing)
            if decision.action == "block":
                db.upsert(decision.scored_ip)
            decisions.append(decision)

        blocked = [d for d in decisions if d.action == "block"]
        log_only = [d for d in decisions if d.action == "log_only"]
        logger.info("[Phase 2] %d block / %d log_only decisions", len(blocked), len(log_only))

        # ── Phase 3: Enforcement ─────────────────────────────────────────────────
        waf_cfg = cfg.get("enforcement", {}).get("aws_waf", {})
        if waf_cfg.get("enabled"):
            logger.warning(
                "  ⚠️  AWS WAF adapter is ENABLED — this incurs AWS costs "
                "(~$1/month per IP set + request fees). Disable in config.yaml if unintended."
            )

        logger.info("[Phase 3] Enforcement …")
        adapter = _get_enforcement_adapter(cfg, logger)
        enforcement_result = _run_enforcement(cfg, db, decisions, logger, adapter=adapter)
        logger.info(
            "  Added: %d | Removed: %d | Skipped: %d",
            enforcement_result.added,
            enforcement_result.removed,
            enforcement_result.skipped,
        )
        for err in enforcement_result.errors:
            logger.warning("  Enforcement error: %s", err)

        # ── Phase 4: TTL expiry sweep ─────────────────────────────────────
        logger.info("[Phase 4] Running TTL expiry sweep …")
        expiry_dry_run = adapter.is_dry_run() if adapter else True
        expiry_result = sweep_expired(
            db=db,
            adapter=adapter,
            dry_run=expiry_dry_run,
        )
        logger.info(
            "  Expired and removed: %d entries (%d actively unenforced)",
            expiry_result.expired_count,
            len(expiry_result.removed_from_enforcer),
        )
        for err in expiry_result.errors:
            logger.warning("  Expiry error: %s", err)

        # ── Phase 4: Audit log ────────────────────────────────────────────
        logger.info("[Phase 4] Writing audit log entry …")
        audit_path = cfg.get("audit", {}).get("log_path", "data/run_history.jsonl")
        audit_logger = AuditLogger(audit_path)

        run_end = datetime.now(timezone.utc)
        elapsed = (run_end - run_start).total_seconds()
        total_active_in_db = len(db.get_active())

        decision_records = [
            {
                "ip": d.scored_ip.ip,
                "action": d.action,
                "score": d.scored_ip.combined_score,
                "sources": d.scored_ip.sources,
                "category": d.scored_ip.category,
                "reason": d.reason,
            }
            for d in decisions
        ]

        expiration_records = [
            {
                "ip": r["ip"],
                "score": r.get("combined_score", 0.0),
                "sources": r.get("sources", []),
                "category": r.get("category", "unknown"),
                "expired_at": r.get("expires_at"),
                "reason": "TTL expired",
            }
            for r in expiry_result.expired_records
        ]

        audit_entry = {
            "run_id": str(uuid.uuid4()),
            "timestamp": run_start.isoformat(),
            "duration_seconds": elapsed,
            "summary": {
                "collected_raw": len(raw_indicators),
                "unique_ips": len(buckets),
                "blocked": len(blocked),
                "log_only": len(log_only),
                "enforced_added": enforcement_result.added,
                "enforced_removed": enforcement_result.removed,
                "enforced_skipped": enforcement_result.skipped,
                "expired_count": expiry_result.expired_count,
                "total_active_in_db": total_active_in_db,
            },
            "decisions": decision_records,
            "expirations": expiration_records,
            "errors": enforcement_result.errors + expiry_result.errors,
        }

        audit_logger.log_run(audit_entry)
        logger.info("  Audit log updated: %s", audit_path)

    # ── Done ─────────────────────────────────────────────────────────────────
    logger.info("═" * 60)
    logger.info("Run complete in %.2fs", elapsed)
    logger.info("═" * 60)

    return decisions


def main() -> None:
    cfg = get_config()
    _setup_logging(cfg)
    run_pipeline(cfg)


if __name__ == "__main__":
    main()
