"""
tests/test_phase2_dedup.py — Unit tests for deduplication logic
"""
from datetime import datetime, timezone

from engine.dedup import deduplicate
from models import RawIndicator


def _indicator(ip: str, source: str, confidence: float, category: str = "brute-force") -> RawIndicator:
    return RawIndicator(
        ip=ip,
        source=source,
        source_confidence=confidence,
        category=category,
        last_reported=datetime.now(timezone.utc),
    )


class TestDeduplicate:
    def test_single_source_single_ip(self):
        indicators = [_indicator("1.2.3.4", "abuseipdb", 85.0)]
        result = deduplicate(indicators)
        assert len(result) == 1
        assert "1.2.3.4" in result
        assert len(result["1.2.3.4"]) == 1
        assert result["1.2.3.4"][0].source_confidence == 85.0

    def test_multi_source_same_ip(self):
        indicators = [
            _indicator("1.2.3.4", "abuseipdb", 85.0),
            _indicator("1.2.3.4", "otx", 70.0),
        ]
        result = deduplicate(indicators)
        assert len(result) == 1
        assert len(result["1.2.3.4"]) == 2
        sources = {ind.source for ind in result["1.2.3.4"]}
        assert sources == {"abuseipdb", "otx"}

    def test_different_ips_separate_buckets(self):
        indicators = [
            _indicator("1.1.1.1", "abuseipdb", 80.0),
            _indicator("2.2.2.2", "otx", 75.0),
        ]
        result = deduplicate(indicators)
        assert len(result) == 2
        assert "1.1.1.1" in result
        assert "2.2.2.2" in result
        assert len(result["1.1.1.1"]) == 1
        assert len(result["2.2.2.2"]) == 1

    def test_within_source_dup_keeps_highest_confidence(self):
        indicators = [
            _indicator("1.2.3.4", "abuseipdb", 60.0),
            _indicator("1.2.3.4", "abuseipdb", 95.0),
            _indicator("1.2.3.4", "abuseipdb", 75.0),
        ]
        result = deduplicate(indicators)
        assert len(result) == 1
        bucket = result["1.2.3.4"]
        assert len(bucket) == 1
        assert bucket[0].source == "abuseipdb"
        assert bucket[0].source_confidence == 95.0

    def test_cidr_and_host_are_different_keys(self):
        indicators = [
            _indicator("10.0.0.0/24", "spamhaus", 80.0),
            _indicator("10.0.0.1", "abuseipdb", 90.0),
        ]
        result = deduplicate(indicators)
        assert len(result) == 2
        assert "10.0.0.0/24" in result
        assert "10.0.0.1" in result

    def test_empty_list_returns_empty_dict(self):
        result = deduplicate([])
        assert result == {}
