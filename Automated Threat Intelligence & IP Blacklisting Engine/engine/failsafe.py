"""
engine/failsafe.py — Fail-safe state machine and operational health tracking
============================================================================
Enforces the core security principle:
  "Missing intelligence must never be interpreted as clean intelligence."

Tracks feed availability states (HEALTHY, DEGRADED, FAIL_SAFE) and prevents
outages from causing unintended blocklist removals or expiry flushes.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class OperationalState(str, Enum):
    HEALTHY = "HEALTHY"          # All enabled feeds healthy; full evaluation
    DEGRADED = "DEGRADED"        # Partial feed failure; prune protection for affected feeds
    FAIL_SAFE = "FAIL_SAFE"      # All feeds failed / DB error; freeze all blocklist removals


@dataclass
class FeedStatus:
    name: str
    healthy: bool
    status_code: int | None = None
    indicator_count: int = 0
    rejected_count: int = 0
    duration_ms: float = 0.0
    error: str | None = None


@dataclass
class PipelineHealthReport:
    operational_state: OperationalState
    feeds: dict[str, FeedStatus] = field(default_factory=dict)
    failed_sources: set[str] = field(default_factory=set)
    healthy_sources: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)


def evaluate_pipeline_health(
    feed_statuses: dict[str, FeedStatus],
    enabled_sources: list[str],
) -> PipelineHealthReport:
    """
    Evaluate the overall pipeline state based on individual feed execution results.
    """
    if not enabled_sources:
        return PipelineHealthReport(
            operational_state=OperationalState.HEALTHY,
            reasons=["No external intel feeds configured as enabled."],
        )

    healthy_sources = {
        name for name in enabled_sources
        if name in feed_statuses and feed_statuses[name].healthy
    }
    failed_sources = {
        name for name in enabled_sources
        if name not in feed_statuses or not feed_statuses[name].healthy
    }

    reasons: list[str] = []

    if not healthy_sources:
        state = OperationalState.FAIL_SAFE
        reasons.append(
            f"All enabled threat feeds failed: {', '.join(failed_sources)}. Entering FAIL-SAFE lock."
        )
    elif failed_sources:
        state = OperationalState.DEGRADED
        reasons.append(
            f"Partial intelligence: Feeds healthy ({', '.join(healthy_sources)}), Feeds failed ({', '.join(failed_sources)}). Degraded mode active."
        )
    else:
        state = OperationalState.HEALTHY
        reasons.append(f"All {len(healthy_sources)} enabled feeds healthy.")

    return PipelineHealthReport(
        operational_state=state,
        feeds=feed_statuses,
        failed_sources=failed_sources,
        healthy_sources=healthy_sources,
        reasons=reasons,
    )


def should_freeze_ip_expiry(
    ip_sources: list[str],
    failed_sources: set[str],
    operational_state: OperationalState,
) -> bool:
    """
    Determine whether an indicator's expiration must be frozen due to feed outage.

    Rule: If the pipeline is in FAIL_SAFE, all expirations are frozen.
          If the pipeline is DEGRADED, an indicator is frozen if all its
          contributing sources are in failed_sources (i.e. the feeds that flagged
          it were offline, so its current threat state is unknown).
    """
    if operational_state == OperationalState.FAIL_SAFE:
        return True

    if operational_state == OperationalState.DEGRADED:
        # If all sources that originally reported this IP are among the failed feeds,
        # we have had no fresh observation from those sources -> freeze expiry.
        if ip_sources and all(src in failed_sources for src in ip_sources):
            logger.info(
                "Freezing expiry for IP with sources %s (feeds are offline in degraded state)",
                ip_sources,
            )
            return True

    return False
