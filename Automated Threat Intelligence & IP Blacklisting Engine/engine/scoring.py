"""
engine/scoring.py — Weighted confidence scoring with multi-source corroboration
================================================================================
Combines normalized source confidences into a single 0–100 score using
source reliability weights and an independent corroboration bonus.
"""
from __future__ import annotations

from models import RawIndicator


def compute_score(
    indicators: list[RawIndicator],
    source_weights: dict[str, float] | None = None,
    multi_source_bonus: float = 10.0,
) -> float:
    """
    Compute a combined 0–100 threat score for an IP.

    Formula:
      base  = Σ(confidence_i × weight_i) / Σ(weight_i)
      bonus = multi_source_bonus if len(unique_sources) >= 2 else 0.0
      score = min(base + bonus, 100.0)
    """
    if not indicators:
        return 0.0

    if source_weights is None:
        source_weights = {}

    weighted_sum = 0.0
    total_weight = 0.0
    unique_sources: set[str] = set()

    for ind in indicators:
        weight = source_weights.get(ind.source, 1.0)
        weighted_sum += ind.source_confidence * weight
        total_weight += weight
        unique_sources.add(ind.source)

    if total_weight <= 0:
        base = 0.0
    else:
        base = weighted_sum / total_weight

    bonus = multi_source_bonus if len(unique_sources) >= 2 else 0.0
    combined = min(base + bonus, 100.0)

    return round(combined, 2)
