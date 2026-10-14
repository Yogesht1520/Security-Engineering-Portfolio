"""
main.py — Threat Intelligence IP Blacklisting Engine
======================================================
Orchestrates one full pipeline run:
  collect → sanitize+bogon filter → deduplicate+score → policy decision →
  fail-safe check → enforce (with circuit breaker & LKG snapshot) → expire → audit

Supports CLI modes:
  python main.py --dry-run      # Preview decisions without mutating firewall/DB
  python main.py --apply        # Live evaluation and firewall enforcement
  python main.py --rollback     # Restore last-known-good (LKG) enforcement state
  python main.py --reconcile    # Audit & reconcile database vs. kernel firewall drift
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone

from audit.logger import AuditLogger
from config import get_config
from engine.dedup import deduplicate
from engine.expiry import sweep_expired
from engine.failsafe import (
    FeedStatus,
    OperationalState,
    PipelineHealthReport,
    evaluate_pipeline_health,
)
from engine.policy import PolicyDecision, apply_policy
from engine.scoring import compute_score_details
from engine.validator import sanitize_indicators
from enforcement import (
    AWSWAFAdapter,
    BaseEnforcer,
    CircuitBreakerError,
    EnforcementResult,
    EnforcerError,
    GuardrailConfig,
    LocalFirewallAdapter,
    SafetyController,
    SnapshotManager,
)
from intel.abuseipdb import AbuseIPDBSource
from intel.base_source import BaseIntelSource, SourceFetchError
from intel.otx import OTXSource
from intel.spamhaus import SpamhausSource
from models import RawIndicator
from reporting.digest import FeedDigest, ReportManager, RunDigest
from siem.forwarder import SiemForwarder
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


def _collect_from_sources_with_health(
    cfg: dict,
) -> tuple[list[RawIndicator], PipelineHealthReport]:
    """Collect indicators from enabled sources while tracking operational health."""
    logger = logging.getLogger("main.collect")

    sources_cfg = cfg.get("sources", {})
    enabled_sources = [
        name for name, s_cfg in sources_cfg.items()
        if s_cfg.get("enabled", False)
    ]

    feed_statuses: dict[str, FeedStatus] = {}
    indicators: list[RawIndicator] = []

    # Safety guard: avoid burning external API quotas during automated test runs
    if "PYTEST_CURRENT_TEST" in os.environ and not cfg.get("_allow_live_network", False):
        logger.info("  [test environment] Skipping live network collection during pytest run")
        for name in enabled_sources:
            feed_statuses[name] = FeedStatus(name=name, healthy=True, indicator_count=0)
        return [], evaluate_pipeline_health(feed_statuses, enabled_sources)

    for name in enabled_sources:
        src_cls = SOURCE_REGISTRY.get(name)
        if not src_cls:
            continue

        src_cfg = sources_cfg.get(name, {})
        api_key = cfg.get("api_keys", {}).get(name)
        start_t = time.perf_counter()
        try:
            source = src_cls(src_cfg, api_key=api_key)
            fetched = source.fetch()
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            logger.info("  [%s] Collected %d indicators in %.1fms", name, len(fetched), duration_ms)
            indicators.extend(fetched)
            feed_statuses[name] = FeedStatus(
                name=name,
                healthy=True,
                status_code=200,
                indicator_count=len(fetched),
                duration_ms=duration_ms,
            )
        except SourceFetchError as exc:
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            logger.warning("  [%s] Fetch failed: %s (duration: %.1fms)", name, exc, duration_ms)
            feed_statuses[name] = FeedStatus(
                name=name,
                healthy=False,
                error=str(exc),
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            logger.warning("  [%s] Unexpected error: %s (duration: %.1fms)", name, exc, duration_ms)
            feed_statuses[name] = FeedStatus(
                name=name,
                healthy=False,
                error=str(exc),
                duration_ms=duration_ms,
            )

    health_report = evaluate_pipeline_health(feed_statuses, enabled_sources)
    return indicators, health_report


def _get_enforcement_adapter(
    cfg: dict,
    logger: logging.Logger | None = None,
    dry_run_override: bool | None = None,
) -> BaseEnforcer | None:
    """Instantiate the active enforcement adapter based on precedence."""
    if logger is None:
        logger = logging.getLogger("main.enforcement")

    fw_cfg = dict(cfg.get("enforcement", {}).get("local_firewall", {}))
    waf_cfg = dict(cfg.get("enforcement", {}).get("aws_waf", {}))

    if dry_run_override is not None:
        fw_cfg["dry_run"] = dry_run_override
        waf_cfg["dry_run"] = dry_run_override

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
    force_apply: bool = False,
    operational_state: OperationalState = OperationalState.HEALTHY,
    siem: SiemForwarder | None = None,
) -> EnforcementResult:
    """
    Execute Phase 3 enforcement with safety circuit breakers, bogon protection,
    and Last-Known-Good snapshot retention.
    """
    if logger is None:
        logger = logging.getLogger("main.enforcement")

    if adapter is None:
        adapter = _get_enforcement_adapter(cfg, logger)

    if adapter is None:
        return EnforcementResult(0, 0, 0)

    if siem is None:
        siem = SiemForwarder(cfg.get("siem", {}))

    # Core Security Principle: Under FAIL_SAFE lockdown, freeze all mutations
    if operational_state == OperationalState.FAIL_SAFE:
        logger.warning("[FAIL-SAFE ACTIVE] Enforcement halted. Preserving existing firewall blocklist untouched.")
        return EnforcementResult(
            0, 0, 0,
            errors=["FAIL-SAFE lock active: All firewall modifications blocked."],
        )

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
    raw_to_add = [r["ip"] for r in active_records if not r.get("enforced")]
    skipped = len(active_records) - len(raw_to_add)

    # Compute to_remove: orphans in current set not in active_ip_set
    to_remove: list[str] = []
    try:
        current = adapter.current_set()
        to_remove = [ip for ip in current if ip not in active_ip_set]
    except Exception as exc:
        logger.warning("Failed to fetch current enforcement set: %s", exc)

    # Safety Guardrails & Protected IP check
    allowlist = cfg.get("policy", {}).get("allowlist", [])
    safety_cfg = GuardrailConfig(
        max_changes_per_run=cfg.get("enforcement", {}).get("max_changes_per_run", 500),
        max_change_percentage=cfg.get("enforcement", {}).get("max_change_percentage", 0.20),
        custom_allowlist=allowlist,
    )
    safety = SafetyController(safety_cfg)

    # Filter out any protected/allowlisted IPs
    safe_to_add, rejected_to_add = safety.filter_safe_ips(raw_to_add)
    if rejected_to_add:
        logger.warning("Safety guard filtered out %d protected IP(s) from to_add", len(rejected_to_add))

    # Rate-of-change circuit breaker verification
    try:
        current_len = len(adapter.current_set()) if not adapter.is_dry_run() else len(active_ip_set)
        safety.verify_rate_of_change(
            current_active_count=current_len,
            to_add_count=len(safe_to_add),
            to_remove_count=len(to_remove),
            force=force_apply,
        )
    except CircuitBreakerError as exc:
        siem.emit_circuit_breaker(
            violation=str(exc),
            planned_adds=len(safe_to_add),
            planned_removes=len(to_remove),
            current_size=current_len,
        )
        return EnforcementResult(
            0, 0, skipped,
            errors=[f"Circuit breaker triggered: {exc}"],
        )

    # Save Last-Known-Good (LKG) snapshot prior to applying mutations
    if not adapter.is_dry_run():
        snapshot_mgr = SnapshotManager(cfg.get("enforcement", {}).get("snapshot_dir", "data/snapshots"))
        try:
            # The desired active state represents our snapshot target
            desired_ips = [r["ip"] for r in active_records]
            snapshot_mgr.save_snapshot(
                enforcer_name=adapter.__class__.__name__,
                active_ips=desired_ips,
                run_id=str(uuid.uuid4()),
            )
        except Exception as exc:
            logger.warning("Failed to write LKG snapshot: %s", exc)

    added_count = 0
    removed_count = 0
    errors: list[str] = []

    # Add unenforced IPs
    if safe_to_add:
        try:
            added_count = adapter.add(safe_to_add)
            rec_by_ip = {r["ip"]: r for r in active_records}
            for ip in safe_to_add:
                if not adapter.is_dry_run():
                    db.set_enforced(ip, True)
                rec = rec_by_ip.get(ip, {})
                siem.emit_block(
                    ip=ip,
                    score=rec.get("combined_score", 0.0),
                    sources=rec.get("sources", []),
                    category=rec.get("category", "suspicious"),
                    reason=rec.get("reason", "Block threshold exceeded"),
                    evidence=rec.get("evidence", []),
                )
        except Exception as exc:
            err_msg = f"Add failed: {exc}"
            logger.error(err_msg)
            errors.append(err_msg)

    # Remove orphan IPs
    if to_remove:
        try:
            removed_count = adapter.remove(to_remove)
            for ip in to_remove:
                if not adapter.is_dry_run():
                    db.set_enforced(ip, False)
                siem.emit_unblock(ip=ip, reason="Orphan rule removed from firewall")
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
    dry_run: bool | None = None,
    force_apply: bool = False,
) -> list[PolicyDecision]:
    """
    Execute the threat intelligence pipeline.
    """
    logger = logging.getLogger("main")
    run_start = datetime.now(timezone.utc)
    logger.info("═" * 60)
    logger.info("Threat Intelligence Blacklisting Engine — run started")
    logger.info("Run timestamp (UTC): %s", run_start.isoformat())
    if dry_run:
        logger.info("MODE: [DRY-RUN] No firewall or database mutations will be executed.")
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
        mock_statuses = {
            ind.source: FeedStatus(name=ind.source, healthy=True, indicator_count=1)
            for ind in raw_indicators
        }
        for src in enabled_sources:
            if src not in mock_statuses:
                mock_statuses[src] = FeedStatus(name=src, healthy=True)
        health_report = evaluate_pipeline_health(mock_statuses, enabled_sources)
        logger.info("  Using provided raw_indicators: %d", len(raw_indicators))
    else:
        raw_indicators, health_report = _collect_from_sources_with_health(cfg)
        logger.info("  Total raw_indicators collected: %d", len(raw_indicators))

    logger.info("  Pipeline operational state: %s", health_report.operational_state.value)
    for r in health_report.reasons:
        logger.info("  Health note: %s", r)

    # ── Phase 1.5: Sanitize & Bogon Filtering ────────────────────────────────
    allowlist = cfg.get("policy", {}).get("allowlist", [])
    sanitized_indicators, rejected_indicators = sanitize_indicators(raw_indicators, allowlist)
    if rejected_indicators:
        logger.info("  Sanitizer: Filtered out %d protected/bogon indicators", len(rejected_indicators))

    # ── Phase 2: Dedup + score + store ────────────────────────────────────────
    logger.info("[Phase 2] Deduplicating and scoring indicators …")
    buckets = deduplicate(sanitized_indicators)
    logger.info("  Unique IP targets after dedup: %d", len(buckets))

    db_path = cfg.get("storage", {}).get("db_path", "data/threat_intel.db")
    with ThreatIntelDB(db_path) as db:
        db.init_schema()

        siem = SiemForwarder(cfg.get("siem", {}))

        # Record feed health telemetry in database & SIEM
        for name, status in health_report.feeds.items():
            db.record_feed_health(
                feed_name=name,
                status="Healthy" if status.healthy else "Failed",
                duration_ms=status.duration_ms,
                indicators_received=status.indicator_count,
                rejected_count=status.rejected_count,
                error_message=status.error,
            )
            siem.emit_feed_status(
                feed_name=name,
                healthy=status.healthy,
                duration_ms=status.duration_ms,
                error=status.error,
            )

        source_weights = {
            name: src.get("weight", 1.0)
            for name, src in cfg.get("sources", {}).items()
        }
        multi_source_bonus = cfg.get("policy", {}).get("multi_source_bonus", 10.0)
        freshness_half_life = cfg.get("policy", {}).get("freshness_half_life_days")
        upstream_lineage = cfg.get("policy", {}).get("upstream_lineage", {})
        policy_cfg = cfg.get("policy", {})

        decisions: list[PolicyDecision] = []
        for ip, bucket in buckets.items():
            score_detail = compute_score_details(
                indicators=bucket,
                source_weights=source_weights,
                multi_source_bonus=multi_source_bonus,
                upstream_lineage=upstream_lineage,
                freshness_half_life_days=freshness_half_life,
            )
            existing = db.get_by_ip(ip)
            decision = apply_policy(
                ip=ip,
                indicators=bucket,
                combined_score=score_detail.combined_score,
                cfg=policy_cfg,
                existing_record=existing,
                score_detail=score_detail,
            )
            if decision.action == "block" and not dry_run:
                db.upsert(
                    scored_ip=decision.scored_ip,
                    status="blocked",
                    reason=decision.reason,
                )
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
        adapter = _get_enforcement_adapter(cfg, logger, dry_run_override=dry_run)
        enforcement_result = _run_enforcement(
            cfg=cfg,
            db=db,
            decisions=decisions,
            logger=logger,
            adapter=adapter,
            force_apply=force_apply,
            operational_state=health_report.operational_state,
            siem=siem,
        )
        logger.info(
            "  Added: %d | Removed: %d | Skipped: %d",
            enforcement_result.added,
            enforcement_result.removed,
            enforcement_result.skipped,
        )
        for err in enforcement_result.errors:
            logger.warning("  Enforcement notice: %s", err)

        # ── Phase 4: TTL expiry sweep ─────────────────────────────────────
        logger.info("[Phase 4] Running TTL expiry sweep …")
        is_expiry_dry = dry_run if dry_run is not None else (adapter.is_dry_run() if adapter else True)
        expiry_result = sweep_expired(
            db=db,
            adapter=adapter,
            dry_run=is_expiry_dry,
            failed_sources=health_report.failed_sources,
            operational_state=health_report.operational_state,
        )
        for ip in expiry_result.removed_from_enforcer:
            siem.emit_unblock(ip=ip, reason="TTL expired; removed from firewall")

        logger.info(
            "  Expired and removed: %d entries (%d actively unenforced, %d frozen)",
            expiry_result.expired_count,
            len(expiry_result.removed_from_enforcer),
            len(expiry_result.frozen_records),
        )
        for err in expiry_result.errors:
            logger.warning("  Expiry notice: %s", err)

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
                "evidence": d.scored_ip.evidence,
                "rationale": d.scored_ip.rationale,
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
            "operational_state": health_report.operational_state.value,
            "dry_run": bool(dry_run),
            "summary": {
                "collected_raw": len(raw_indicators),
                "rejected_bogons": len(rejected_indicators),
                "unique_ips": len(buckets),
                "blocked": len(blocked),
                "log_only": len(log_only),
                "enforced_added": enforcement_result.added,
                "enforced_removed": enforcement_result.removed,
                "enforced_skipped": enforcement_result.skipped,
                "expired_count": expiry_result.expired_count,
                "frozen_count": len(expiry_result.frozen_records),
                "total_active_in_db": total_active_in_db,
            },
            "decisions": decision_records,
            "expirations": expiration_records,
            "rejected_indicators": rejected_indicators,
            "errors": enforcement_result.errors + expiry_result.errors,
        }

        audit_logger.log_run(audit_entry)
        logger.info("  Audit log updated: %s", audit_path)

        # ── Phase 4.5: Executive Reporting & Webhook Alerts ─────────────────
        report_cfg = cfg.get("reporting", {})
        if report_cfg.get("enabled", True):
            report_mgr = ReportManager(report_cfg)
            cb_tripped = any("Circuit breaker triggered" in str(e) for e in enforcement_result.errors)
            cb_reason = next((str(e) for e in enforcement_result.errors if "Circuit breaker triggered" in str(e)), "")

            feed_digests = [
                FeedDigest(
                    name=s.name,
                    healthy=s.healthy,
                    duration_ms=s.duration_ms,
                    indicators_received=s.indicator_count,
                    rejected_count=s.rejected_count,
                    error=s.error,
                )
                for s in health_report.feeds.values()
            ]

            run_digest = RunDigest(
                run_id=audit_entry["run_id"],
                timestamp=run_start,
                duration_seconds=elapsed,
                operational_state=health_report.operational_state.value,
                collected_raw=len(raw_indicators),
                unique_ips=len(buckets),
                blocked_count=len(blocked),
                log_only_count=len(log_only),
                enforced_added=enforcement_result.added,
                enforced_removed=enforcement_result.removed,
                enforced_skipped=enforcement_result.skipped,
                expired_count=expiry_result.expired_count,
                total_active_in_db=total_active_in_db,
                is_dry_run=bool(dry_run),
                circuit_breaker_tripped=cb_tripped,
                circuit_breaker_reason=cb_reason,
                feeds=feed_digests,
                errors=enforcement_result.errors + expiry_result.errors,
            )

            report_file = report_mgr.save_markdown_digest(run_digest)
            logger.info("  Executive report saved: %s", report_file)

            if report_mgr.webhook_url:
                sent = report_mgr.dispatch_webhook(run_digest)
                if sent:
                    logger.info("  Webhook alert dispatched successfully")

    logger.info("═" * 60)
    logger.info("Run complete in %.2fs [%s]", elapsed, health_report.operational_state.value)
    logger.info("═" * 60)

    return decisions


def run_rollback(cfg: dict) -> None:
    """Execute emergency rollback to the last-known-good snapshot."""
    logger = logging.getLogger("main.rollback")
    adapter = _get_enforcement_adapter(cfg, logger)
    if not adapter:
        logger.error("No active enforcement adapter configured for rollback.")
        return

    snapshot_dir = cfg.get("enforcement", {}).get("snapshot_dir", "data/snapshots")
    mgr = SnapshotManager(snapshot_dir)
    try:
        res = mgr.rollback(adapter=adapter, dry_run=adapter.is_dry_run())
        logger.info(
            "Rollback successful: Restored snapshot %s (+%d added, -%d removed)",
            res["snapshot_id"],
            res["added"],
            res["removed"],
        )
    except Exception as exc:
        logger.error("Rollback failed: %s", exc)


def run_reconciliation(cfg: dict, dry_run: bool | None = None) -> None:
    """Compare desired database state vs. active kernel firewall state and reconcile."""
    logger = logging.getLogger("main.reconcile")
    adapter = _get_enforcement_adapter(cfg, logger, dry_run_override=dry_run)
    if not adapter:
        logger.error("No active enforcement adapter configured for reconciliation.")
        return

    db_path = cfg.get("storage", {}).get("db_path", "data/threat_intel.db")
    with ThreatIntelDB(db_path) as db:
        active_records = db.get_active()
        desired_set = {r["ip"] for r in active_records}

        try:
            current_set = adapter.current_set()
        except EnforcerError as exc:
            logger.warning("Could not query active firewall state: %s", exc)
            current_set = set()

        missing_in_fw = list(desired_set - current_set)
        orphan_in_fw = list(current_set - desired_set)

        logger.info("═" * 60)
        logger.info("Firewall Reconciliation Report")
        logger.info("  Desired state (Database Active): %d", len(desired_set))
        logger.info("  Actual state (Firewall Set)    : %d", len(current_set))
        logger.info("  Missing in firewall (Drift)    : %d", len(missing_in_fw))
        logger.info("  Orphan in firewall (Drift)     : %d", len(orphan_in_fw))
        logger.info("═" * 60)

        siem = SiemForwarder(cfg.get("siem", {}))
        if missing_in_fw or orphan_in_fw:
            siem.emit_drift(detected_orphans=orphan_in_fw, missing_in_fw=missing_in_fw)

        if not missing_in_fw and not orphan_in_fw:
            logger.info("State is fully reconciled. No drift detected.")
            return

        if adapter.is_dry_run():
            logger.info("[DRY-RUN] Drift correction simulated.")
            return

        try:
            if missing_in_fw:
                added = adapter.add(missing_in_fw)
                logger.info("Reconciled: Added %d missing entries to firewall", added)

            if orphan_in_fw:
                removed = adapter.remove(orphan_in_fw)
                logger.info("Reconciled: Removed %d orphan entries from firewall", removed)
        except EnforcerError as exc:
            logger.warning("Reconciliation notice: %s", exc)


def print_decision_explanation(ip: str, cfg: dict) -> None:
    """Print an evidence-backed explanation for a target IP address."""
    db_path = cfg.get("storage", {}).get("db_path", "data/threat_intel.db")
    with ThreatIntelDB(db_path) as db:
        record = db.get_by_ip(ip)
        if not record:
            print(f"\n[?] Indicator {ip} not found in database.\n")
            return

        status = "BLOCK" if record.get("enforced") else "MONITOR / LOG-ONLY"
        score = record.get("combined_score", 0.0)
        sources = record.get("sources", [])
        cat = record.get("category", "unknown")
        first_seen = record.get("first_seen")
        expires = record.get("expires_at")

        print("\n" + "=" * 55)
        print(f"Indicator : {ip}")
        print(f"Decision  : {status}")
        print(f"Confidence: {score:.1f} / 100")
        print(f"Category  : {cat}")
        print("-" * 55)
        print("Intelligence Sources:")
        for s in sources:
            print(f"  • {s}")
        print("-" * 55)
        print(f"Lifecycle:")
        print(f"  First Seen : {first_seen}")
        print(f"  Expires At : {expires}")
        print("=" * 55 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated Threat Intelligence & IP Blacklisting Engine")
    parser.add_argument("--dry-run", action="store_true", help="Simulate pipeline without modifying firewall or DB")
    parser.add_argument("--apply", action="store_true", help="Execute live evaluation and firewall enforcement")
    parser.add_argument("--rollback", action="store_true", help="Restore Last-Known-Good (LKG) enforcement state")
    parser.add_argument("--reconcile", action="store_true", help="Audit and resolve drift between DB and firewall")
    parser.add_argument("--force-apply", action="store_true", help="Override circuit breakers for large batch updates")
    parser.add_argument("--siem", action="store_true", help="Stream security events to SIEM (data/siem_events.jsonl)")
    parser.add_argument("--explain", type=str, metavar="IP", help="Explain intelligence decision and evidence for IP")

    args = parser.parse_args()
    cfg = get_config()
    _setup_logging(cfg)

    if args.siem:
        if "siem" not in cfg:
            cfg["siem"] = {}
        cfg["siem"]["enabled"] = True

    if args.explain:
        print_decision_explanation(args.explain, cfg)
        return

    if args.rollback:
        run_rollback(cfg)
        return

    if args.reconcile:
        is_dry = True if args.dry_run else (False if args.apply else None)
        run_reconciliation(cfg, dry_run=is_dry)
        return

    is_dry = True if args.dry_run else (False if args.apply else None)
    run_pipeline(cfg, dry_run=is_dry, force_apply=args.force_apply)


if __name__ == "__main__":
    main()
