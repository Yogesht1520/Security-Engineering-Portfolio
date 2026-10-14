"""
engine/expiry.py — TTL expiry sweep logic with fail-safe freeze protection
==========================================================================
Identifies expired indicators (where expires_at < now UTC),
removes them from active enforcement points (ipset / AWS WAF),
and purges them from the database.

Security Principle: Missing intelligence is NOT clean intelligence.
If a contributing threat feed is currently offline, indicator expiration
is frozen until that feed recovers.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from enforcement.base_adapter import BaseEnforcer
from engine.failsafe import OperationalState, should_freeze_ip_expiry
from storage.db import ThreatIntelDB

logger = logging.getLogger(__name__)


@dataclass
class ExpiryResult:
    """Summary of records purged during a TTL expiry sweep."""
    expired_count: int = 0
    expired_records: list[dict[str, Any]] = field(default_factory=list)
    removed_from_enforcer: list[str] = field(default_factory=list)
    frozen_records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def sweep_expired(
    db: ThreatIntelDB,
    adapter: BaseEnforcer | None = None,
    now: datetime | str | None = None,
    dry_run: bool = False,
    failed_sources: set[str] | None = None,
    operational_state: OperationalState | None = None,
) -> ExpiryResult:
    """
    Scan for expired IP records, remove them from firewall/WAF, and purge from DB.
    """
    # Fail-safe lockdown check: If total feed outage, freeze everything
    if operational_state == OperationalState.FAIL_SAFE:
        logger.warning("[FAIL-SAFE ACTIVE] Entire pipeline is in FAIL-SAFE mode. Freezing all blocklist expirations.")
        return ExpiryResult(
            expired_count=0,
            expired_records=[],
            removed_from_enforcer=[],
            frozen_records=[],
            errors=["FAIL-SAFE lock active: Expirations suspended to prevent false unblocking."],
        )

    all_expired_rows = db.get_expired(now=now)
    if not all_expired_rows:
        return ExpiryResult(0, [], [], [], [])

    # Filter out indicators whose sources are currently offline
    eligible_rows: list[dict[str, Any]] = []
    frozen_rows: list[dict[str, Any]] = []
    failed_set = failed_sources or set()
    current_state = operational_state or OperationalState.HEALTHY

    for row in all_expired_rows:
        sources = row.get("sources", [])
        if should_freeze_ip_expiry(sources, failed_set, current_state):
            frozen_rows.append(row)
        else:
            eligible_rows.append(row)

    if frozen_rows:
        logger.info(
            "Fail-safe protection: Froze %d expired indicator(s) because their intelligence feed(s) are offline",
            len(frozen_rows),
        )

    if not eligible_rows:
        return ExpiryResult(0, [], [], frozen_rows, [])

    to_unenforce = [r["ip"] for r in eligible_rows if r.get("enforced") == 1]
    removed_from_enforcer: list[str] = []
    errors: list[str] = []

    if dry_run:
        logger.info(
            "[DRY-RUN] Expiry sweep: %d records eligible for purge (%d currently enforced, %d frozen)",
            len(eligible_rows),
            len(to_unenforce),
            len(frozen_rows),
        )
        return ExpiryResult(
            expired_count=len(eligible_rows),
            expired_records=eligible_rows,
            removed_from_enforcer=to_unenforce,
            frozen_records=frozen_rows,
            errors=[],
        )

    # 1. Unenforce active IPs from the firewall/WAF
    if adapter is not None and to_unenforce:
        try:
            adapter.remove(to_unenforce)
            removed_from_enforcer.extend(to_unenforce)
        except Exception as exc:
            err_msg = f"Enforcer removal failed during expiry: {exc}"
            logger.error(err_msg)
            errors.append(err_msg)

    # 2. Purge eligible rows from persistent database
    for row in eligible_rows:
        try:
            db.delete(row["ip"])
        except Exception as exc:
            err_msg = f"DB deletion failed for {row['ip']}: {exc}"
            logger.error(err_msg)
            errors.append(err_msg)

    return ExpiryResult(
        expired_count=len(eligible_rows),
        expired_records=eligible_rows,
        removed_from_enforcer=removed_from_enforcer,
        frozen_records=frozen_rows,
        errors=errors,
    )
