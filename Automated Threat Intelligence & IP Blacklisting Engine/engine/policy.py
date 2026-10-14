"""
engine/policy.py — Threshold evaluation, action assignment, allowlist suppression, and TTL management
======================================================================================================
Evaluates deduplicated and scored indicators against confidence thresholds
to determine whether an IP should be blocked or logged, enforces protected
allowlists, and calculates its active TTL window.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from engine.scoring import ScoreDetail
from engine.validator import is_protected_network, parse_ip_or_network
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
    score_detail: ScoreDetail | None = None,
) -> PolicyDecision:
    """
    Decide whether to block or log an IP and compute its TTL window.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    threshold = cfg.get("confidence_threshold", 70)
    ttl_days = cfg.get("ttl_days", 7)
    allowlist = cfg.get("allowlist", [])

    # Check allowlist / protected IP status
    parsed = parse_ip_or_network(ip)
    is_protected = False
    prot_reason = ""
    if parsed is not None:
        is_protected, prot_reason = is_protected_network(parsed, allowlist)

    if is_protected:
        action: Literal["block", "log_only"] = "log_only"
        policy_note = f"PROTECTED ({prot_reason}); forced log_only"
    else:
        action = "block" if combined_score >= threshold else "log_only"
        policy_note = f"score {combined_score:.1f} {'>=' if action == 'block' else '<'} threshold {threshold}"

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
            first_seen = now
            expires_at = now + timedelta(days=ttl_days)
            reason = f"Re-flagged after expiry; {policy_note} ({action})"
        else:
            orig_first_seen = _parse_dt(existing_record.get("first_seen"))
            first_seen = orig_first_seen if orig_first_seen is not None else now
            expires_at = now + timedelta(days=ttl_days)
            reason = f"TTL renewed; {policy_note} ({action})"
    else:
        first_seen = now
        expires_at = now + timedelta(days=ttl_days)
        reason = f"New indicator; {policy_note} ({action})"

    # Extract evidence & rationale
    evidence_dicts: list[dict[str, Any]] = []
    rationale_lines: list[str] = []
    if score_detail is not None:
        evidence_dicts = [asdict(ev) for ev in score_detail.evidence]
        rationale_lines = list(score_detail.rationale)
    else:
        for ind in indicators:
            evidence_dicts.append({
                "source": ind.source,
                "confidence": ind.source_confidence,
                "category": ind.category,
                "last_reported": ind.last_reported.isoformat() if hasattr(ind.last_reported, "isoformat") else str(ind.last_reported),
            })

    version = 6 if ":" in ip else 4

    scored_ip = ScoredIP(
        ip=ip,
        combined_score=combined_score,
        sources=sources,
        category=category,
        first_seen=first_seen,
        expires_at=expires_at,
        evidence=evidence_dicts,
        rationale=rationale_lines,
        ip_version=version,
    )

    return PolicyDecision(
        scored_ip=scored_ip,
        action=action,
        reason=reason,
    )
