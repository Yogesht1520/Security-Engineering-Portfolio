"""
engine/expiry.py — TTL expiry sweep logic
==========================================
Identifies expired indicators (where expires_at < now UTC),
removes them from active enforcement points (ipset / AWS WAF),
and purges them from the database. Prevents indefinite blocklist growth.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from enforcement.base_adapter import BaseEnforcer
from storage.db import ThreatIntelDB

logger = logging.getLogger(__name__)


@dataclass
class ExpiryResult:
    """Summary of records purged during a TTL expiry sweep."""

    expired_count: int = 0
    expired_records: list[dict[str, Any]] = field(default_factory=list)
    removed_from_enforcer: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def sweep_expired(
    db: ThreatIntelDB,
    adapter: BaseEnforcer | None = None,
    now: datetime | str | None = None,
    dry_run: bool = False,
) -> ExpiryResult:
    """
    Scan for expired IP records, remove them from firewall/WAF, and purge from DB.

    Args:
        db: Open ThreatIntelDB instance.
        adapter: Enforcement adapter to remove actively enforced IPs from.
        now: Optional reference timestamp (defaults to current UTC time).
        dry_run: If True, simulates expiration without deleting or calling firewall.

    Returns:
        ExpiryResult containing counts, affected IPs, and any errors.
    """
    expired_rows = db.get_expired(now=now)
    if not expired_rows:
        return ExpiryResult(0, [], [], [])

    to_unenforce = [r["ip"] for r in expired_rows if r.get("enforced") == 1]
    removed_from_enforcer: list[str] = []
    errors: list[str] = []

    if dry_run:
        logger.info(
            "[DRY-RUN] Expiry sweep: %d records eligible for purge (%d currently enforced)",
            len(expired_rows),
            len(to_unenforce),
        )
        return ExpiryResult(
            expired_count=len(expired_rows),
            expired_records=expired_rows,
            removed_from_enforcer=to_unenforce,
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

    # 2. Purge from persistent database
    for row in expired_rows:
        try:
            db.delete(row["ip"])
        except Exception as exc:
            err_msg = f"DB deletion failed for {row['ip']}: {exc}"
            logger.error(err_msg)
            errors.append(err_msg)

    return ExpiryResult(
        expired_count=len(expired_rows),
        expired_records=expired_rows,
        removed_from_enforcer=removed_from_enforcer,
        errors=errors,
    )
