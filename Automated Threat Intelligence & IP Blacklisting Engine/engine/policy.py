"""
engine/policy.py — Threshold evaluation, action assignment, and TTL management
================================================================================
Evaluates deduplicated and scored indicators against confidence thresholds
to determine whether an IP should be blocked or logged, and calculates
its active TTL window.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from models import RawIndicator, ScoredIP


@dataclass
class PolicyDecision:
    """The outcome of evaluating a scored IP against engine policies."""
    scored_ip: ScoredIP
    action: Literal["block", "log_only"]
    reason: str


def _parse_dt(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        dt = datetime.fromisoformat(val)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    return None


def apply_policy(
    ip: str,
    indicators: list[RawIndicator],
    combined_score: float,
    cfg: dict[str, Any],
    existing_record: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> PolicyDecision:
    """
    Decide whether to block or log an IP and compute its TTL window.

    Args:
        ip: The target IPv4 or CIDR string.
        indicators: Corroborating RawIndicator objects for this IP.
        combined_score: Calculated combined score (0–100).
        cfg: The policy configuration dict (e.g. confidence_threshold, ttl_days).
        existing_record: Existing DB row dict if previously seen, else None.
        now: Optional reference timestamp (defaults to current UTC time).

    Returns:
        PolicyDecision containing the ScoredIP, action ('block' | 'log_only'), and audit reason.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    threshold = cfg.get("confidence_threshold", 70)
    ttl_days = cfg.get("ttl_days", 7)

    action: Literal["block", "log_only"] = "block" if combined_score >= threshold else "log_only"

    # Category: prioritize highest confidence indicator's category
    if indicators:
        sorted_by_conf = sorted(indicators, key=lambda i: i.source_confidence, reverse=True)
        category = sorted_by_conf[0].category or "suspicious"
        sources = sorted(list({i.source for i in indicators}))
    else:
        category = "suspicious"
        sources = []

    # TTL Calculation
    if existing_record is not None:
        existing_expires = _parse_dt(existing_record.get("expires_at"))
        is_expired = existing_expires is not None and existing_expires < now

        if is_expired:
            # Re-flagged post-expiry: treated as new indicator with fresh first_seen
            first_seen = now
            expires_at = now + timedelta(days=ttl_days)
            reason = (
                f"Re-flagged after expiry; score {combined_score:.1f} "
                f"{'>=' if action == 'block' else '<'} threshold {threshold} ({action})"
            )
        else:
            # Active IP: renew TTL (reset expiry clock) while preserving original first_seen
            orig_first_seen = _parse_dt(existing_record.get("first_seen"))
            first_seen = orig_first_seen if orig_first_seen is not None else now
            expires_at = now + timedelta(days=ttl_days)
            reason = (
                f"TTL renewed; score {combined_score:.1f} "
                f"{'>=' if action == 'block' else '<'} threshold {threshold} ({action})"
            )
    else:
        first_seen = now
        expires_at = now + timedelta(days=ttl_days)
        reason = (
            f"New indicator; score {combined_score:.1f} "
            f"{'>=' if action == 'block' else '<'} threshold {threshold} ({action})"
        )

    scored_ip = ScoredIP(
        ip=ip,
        combined_score=combined_score,
        sources=sources,
        category=category,
        first_seen=first_seen,
        expires_at=expires_at,
    )

    return PolicyDecision(
        scored_ip=scored_ip,
        action=action,
        reason=reason,
    )
