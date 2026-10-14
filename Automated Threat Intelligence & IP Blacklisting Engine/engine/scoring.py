"""
engine/scoring.py — Weighted confidence scoring with provenance and freshness decay
===================================================================================
Combines normalized source confidences into a single 0–100 score using:
- Source reliability weights
- Freshness time decay (half-life)
- Provenance de-aliasing (independent corroboration across upstream roots)
- Strict clamping to [0.0, 100.0]
- Detailed evidence dossiers for decision explanation
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

from models import RawIndicator


@dataclass
class IndicatorEvidence:
    """Detailed evidence for a single indicator observation."""
    source: str
    reported_confidence: float
    normalized_confidence: float
    decayed_confidence: float
    freshness_factor: float
    category: str
    last_reported: str
    upstream_root: str


@dataclass
class ScoreDetail:
    """Comprehensive scoring evaluation and evidence breakdown."""
    combined_score: float
    base_score: float
    bonus_applied: float
    independent_sources: list[str] = field(default_factory=list)
    is_independently_corroborated: bool = False
    evidence: list[IndicatorEvidence] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)


def _get_upstream_root(source: str, upstream_lineage: dict[str, str | list[str]] | None) -> str:
    """Resolve the root origin of a source to prevent syndicate double-counting."""
    if not upstream_lineage or source not in upstream_lineage:
        return source
    val = upstream_lineage[source]
    if isinstance(val, list):
        return val[0] if val else source
    return str(val)


def compute_score_details(
    indicators: list[RawIndicator],
    source_weights: dict[str, float] | None = None,
    multi_source_bonus: float = 10.0,
    upstream_lineage: dict[str, str | list[str]] | None = None,
    freshness_half_life_days: float | None = None,
    now: datetime | None = None,
) -> ScoreDetail:
    """
    Compute a combined 0–100 threat score and return a complete evidence dossier.
    """
    if not indicators:
        return ScoreDetail(
            combined_score=0.0,
            base_score=0.0,
            bonus_applied=0.0,
            rationale=["No indicator evidence provided."],
        )

    if source_weights is None:
        source_weights = {}

    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    weighted_sum = 0.0
    total_weight = 0.0
    evidence_list: list[IndicatorEvidence] = []
    root_to_sources: dict[str, set[str]] = {}

    for ind in indicators:
        # 1. Normalize confidence to 0–100
        raw_conf = max(0.0, min(float(ind.source_confidence), 100.0))

        # 2. Freshness decay
        decay_factor = 1.0
        if freshness_half_life_days and freshness_half_life_days > 0:
            last_rep = ind.last_reported
            if last_rep.tzinfo is None:
                last_rep = last_rep.replace(tzinfo=timezone.utc)
            age_days = max(0.0, (now - last_rep).total_seconds() / 86400.0)
            decay_factor = math.pow(0.5, age_days / freshness_half_life_days)

        decayed_conf = raw_conf * decay_factor

        # 3. Source weight
        weight = max(0.0, source_weights.get(ind.source, 1.0))
        weighted_sum += decayed_conf * weight
        total_weight += weight

        # 4. Upstream provenance tracking
        root = _get_upstream_root(ind.source, upstream_lineage)
        if root not in root_to_sources:
            root_to_sources[root] = set()
        root_to_sources[root].add(ind.source)

        last_rep_str = (
            ind.last_reported.isoformat()
            if hasattr(ind.last_reported, "isoformat")
            else str(ind.last_reported)
        )

        evidence_list.append(
            IndicatorEvidence(
                source=ind.source,
                reported_confidence=raw_conf,
                normalized_confidence=round(raw_conf, 2),
                decayed_confidence=round(decayed_conf, 2),
                freshness_factor=round(decay_factor, 3),
                category=ind.category or "unknown",
                last_reported=last_rep_str,
                upstream_root=root,
            )
        )

    base = weighted_sum / total_weight if total_weight > 0 else 0.0

    # 5. Independent corroboration check (distinct upstream roots)
    independent_roots = sorted(list(root_to_sources.keys()))
    is_corroborated = len(independent_roots) >= 2
    bonus = multi_source_bonus if is_corroborated else 0.0

    # 6. Clamp final score to 0–100
    combined = max(0.0, min(100.0, base + bonus))

    # 7. Formulate rationale
    rationale = []
    if is_corroborated:
        rationale.append(
            f"Independent corroboration across {len(independent_roots)} distinct upstream roots: {', '.join(independent_roots)} (+{bonus:.1f} bonus)"
        )
    elif len(indicators) > 1 and len(independent_roots) == 1:
        rationale.append(
            f"Multiple indicators share common upstream lineage '{independent_roots[0]}' (duplicate reporting; no multi-source bonus)"
        )
    else:
        rationale.append(f"Single source evaluation ({evidence_list[0].source})")

    if freshness_half_life_days:
        rationale.append(f"Freshness decay applied with {freshness_half_life_days:.1f}-day half-life")

    rationale.append(f"Base score: {base:.2f}, Final clamped score: {combined:.2f}")

    return ScoreDetail(
        combined_score=round(combined, 2),
        base_score=round(base, 2),
        bonus_applied=bonus,
        independent_sources=independent_roots,
        is_independently_corroborated=is_corroborated,
        evidence=evidence_list,
        rationale=rationale,
    )


def compute_score(
    indicators: list[RawIndicator],
    source_weights: dict[str, float] | None = None,
    multi_source_bonus: float = 10.0,
    upstream_lineage: dict[str, str | list[str]] | None = None,
    freshness_half_life_days: float | None = None,
    now: datetime | None = None,
) -> float:
    """
    Compute a combined 0–100 threat score for an IP.
    Backwards-compatible wrapper around compute_score_details.
    """
    detail = compute_score_details(
        indicators=indicators,
        source_weights=source_weights,
        multi_source_bonus=multi_source_bonus,
        upstream_lineage=upstream_lineage,
        freshness_half_life_days=freshness_half_life_days,
        now=now,
    )
    return detail.combined_score
