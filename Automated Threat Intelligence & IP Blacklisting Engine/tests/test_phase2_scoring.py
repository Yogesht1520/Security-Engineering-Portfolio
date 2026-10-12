"""
tests/test_phase2_scoring.py — Unit tests for weighted scoring and corroboration bonus
"""
from datetime import datetime, timezone

from engine.scoring import compute_score
from models import RawIndicator


def _ind(source: str, confidence: float) -> RawIndicator:
    return RawIndicator(
        ip="1.2.3.4",
        source=source,
        source_confidence=confidence,
        category="malware",
        last_reported=datetime.now(timezone.utc),
    )


class TestScoring:
    def test_single_source_no_bonus(self):
        indicators = [_ind("abuseipdb", 80.0)]
        weights = {"abuseipdb": 1.0}
        score = compute_score(indicators, source_weights=weights, multi_source_bonus=10.0)
        assert score == 80.0

    def test_two_sources_bonus_applied(self):
        # abuseipdb: 80 * 1.0 = 80
        # otx: 60 * 1.0 = 60
        # avg = 140 / 2 = 70.0; bonus = 10.0 -> score = 80.0
        indicators = [_ind("abuseipdb", 80.0), _ind("otx", 60.0)]
        weights = {"abuseipdb": 1.0, "otx": 1.0}
        score = compute_score(indicators, source_weights=weights, multi_source_bonus=10.0)
        assert score == 80.0

    def test_three_sources_bonus_only_once(self):
        # 3 sources: bonus applied exactly once, not twice
        indicators = [_ind("abuseipdb", 80.0), _ind("otx", 80.0), _ind("spamhaus", 80.0)]
        weights = {"abuseipdb": 1.0, "otx": 1.0, "spamhaus": 1.0}
        score = compute_score(indicators, source_weights=weights, multi_source_bonus=10.0)
        assert score == 90.0

    def test_score_capped_at_100(self):
        indicators = [_ind("abuseipdb", 98.0), _ind("otx", 95.0)]
        score = compute_score(indicators, source_weights={"abuseipdb": 1.0, "otx": 1.0}, multi_source_bonus=15.0)
        assert score == 100.0

    def test_unknown_source_uses_default_weight_1(self):
        indicators = [_ind("custom_feed", 75.0)]
        # custom_feed not in weights dict
        score = compute_score(indicators, source_weights={"abuseipdb": 1.0}, multi_source_bonus=10.0)
        assert score == 75.0

    def test_higher_weight_source_pulls_score_up(self):
        # abuseipdb weight=1.0, spamhaus weight=0.2
        # abuseipdb=90, spamhaus=50
        # weighted_avg = (90*1.0 + 50*0.2) / 1.2 = (90 + 10) / 1.2 = 83.33
        # without bonus: 83.33
        indicators = [_ind("abuseipdb", 90.0), _ind("spamhaus", 50.0)]
        weights = {"abuseipdb": 1.0, "spamhaus": 0.2}
        score = compute_score(indicators, source_weights=weights, multi_source_bonus=0.0)
        assert score == 83.33
        assert score > 70.0  # closer to 90 than simple average 70
