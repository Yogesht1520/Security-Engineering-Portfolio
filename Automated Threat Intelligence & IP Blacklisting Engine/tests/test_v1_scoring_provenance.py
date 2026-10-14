"""
tests/test_v1_scoring_provenance.py — Tests for provenance de-aliasing, freshness decay, and clamping
"""
from datetime import datetime, timedelta, timezone

from engine.scoring import compute_score, compute_score_details
from models import RawIndicator


def _ind(source: str, confidence: float, days_ago: float = 0.0) -> RawIndicator:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return RawIndicator(
        ip="198.51.100.10",
        source=source,
        source_confidence=confidence,
        category="bruteforce",
        last_reported=dt,
    )


class TestScoringProvenance:
    def test_independent_corroboration_applies_bonus(self):
        # Two independent sources with distinct lineage roots
        indicators = [_ind("abuseipdb", 70.0), _ind("otx", 70.0)]
        detail = compute_score_details(indicators, source_weights={"abuseipdb": 1.0, "otx": 1.0}, multi_source_bonus=10.0)
        assert detail.is_independently_corroborated is True
        assert detail.bonus_applied == 10.0
        assert detail.combined_score == 80.0

    def test_upstream_lineage_dealiasing_prevents_duplicate_bonus(self):
        # Two sources both republishing the same underlying root 'spamhaus_drop'
        indicators = [_ind("spamhaus", 80.0), _ind("mirror_spamhaus", 80.0)]
        lineage = {
            "spamhaus": "spamhaus_root",
            "mirror_spamhaus": "spamhaus_root",
        }
        detail = compute_score_details(
            indicators,
            source_weights={"spamhaus": 1.0, "mirror_spamhaus": 1.0},
            multi_source_bonus=10.0,
            upstream_lineage=lineage,
        )
        assert detail.is_independently_corroborated is False
        assert detail.bonus_applied == 0.0
        assert detail.combined_score == 80.0
        assert any("duplicate reporting" in r for r in detail.rationale)

    def test_freshness_half_life_decay(self):
        # Indicator 14 days old with a 14-day half-life should have its confidence halved (50%)
        old_ind = _ind("abuseipdb", 80.0, days_ago=14.0)
        detail = compute_score_details([old_ind], freshness_half_life_days=14.0)
        assert abs(detail.combined_score - 40.0) < 1.0
        assert detail.evidence[0].freshness_factor == 0.5

    def test_strict_score_clamping(self):
        # High confidence + large bonus cannot exceed 100
        indicators = [_ind("source1", 99.0), _ind("source2", 99.0)]
        score = compute_score(indicators, multi_source_bonus=50.0)
        assert score == 100.0
