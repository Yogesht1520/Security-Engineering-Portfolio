"""
tests/test_phase1_sources.py — Phase 1: intel source unit tests
================================================================
All network calls are mocked — no real HTTP ever made in the test suite.
Each source must return a non-empty list[RawIndicator] from mocked data.

Run: pytest tests/test_phase1_sources.py -v
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import RawIndicator
from intel.base_source import BaseIntelSource, SourceFetchError


# ─────────────────────────────────────────────────────────────────
# Helpers / fixtures
# ─────────────────────────────────────────────────────────────────

def _mock_response(status_code: int, json_body: dict | None = None, text: str = "") -> MagicMock:
    """Build a mock requests.Response object."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.ok = (200 <= status_code < 300)
    mock.text = text if text else (json.dumps(json_body) if json_body else "")
    mock.json.return_value = json_body or {}
    mock.headers = {"X-RateLimit-Remaining": "999"}
    return mock


def _make_source_cfg(**overrides) -> dict:
    base = {
        "enabled": True,
        "max_age_days": 30,
        "min_confidence": 50,
        "limit": 10,
        "weight": 1.0,
        "pulse_limit": 5,
    }
    base.update(overrides)
    return base


# ═════════════════════════════════════════════════════════════════
# 1. BaseIntelSource ABC
# ═════════════════════════════════════════════════════════════════

class TestBaseIntelSource:
    def test_cannot_instantiate_abc_directly(self):
        with pytest.raises(TypeError):
            BaseIntelSource({})  # noqa: abstract class

    def test_is_enabled_reads_cfg(self):
        """A concrete subclass with enabled=True must return True."""
        class _Concrete(BaseIntelSource):
            SOURCE_NAME = "test"
            def fetch(self): return []

        src = _Concrete({"enabled": True})
        assert src.is_enabled() is True

        src_off = _Concrete({"enabled": False})
        assert src_off.is_enabled() is False

    def test_api_key_stored(self):
        class _Concrete(BaseIntelSource):
            SOURCE_NAME = "test"
            def fetch(self): return []

        src = _Concrete({}, api_key="my-secret-key")
        assert src.api_key == "my-secret-key"


# ═════════════════════════════════════════════════════════════════
# 2. AbuseIPDBSource
# ═════════════════════════════════════════════════════════════════

class TestAbuseIPDBSource:
    """Mocked unit tests — no real HTTP calls."""

    _SAMPLE_RESPONSE = {
        "meta": {"generatedAt": "2024-01-01T00:00:00+00:00"},
        "data": [
            {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 90,
                "countryCode": "CN",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Some ISP",
                "domain": "example.com",
                "lastReportedAt": "2024-01-01T12:00:00+00:00",
                "categories": [18, 22],  # brute-force, ssh-brute-force
            },
            {
                "ipAddress": "5.6.7.8",
                "abuseConfidenceScore": 75,
                "countryCode": "RU",
                "usageType": "Fixed Line ISP",
                "isp": "Another ISP",
                "domain": "other.com",
                "lastReportedAt": "2024-01-02T06:00:00+00:00",
                "categories": [11],  # email-spam
            },
            {
                "ipAddress": "9.10.11.12",
                "abuseConfidenceScore": 55,
                "countryCode": "US",
                "usageType": "Unknown",
                "isp": "ISP LLC",
                "domain": "",
                "lastReportedAt": None,  # missing timestamp — must default gracefully
                "categories": [],
            },
        ],
    }

    def _make_source(self, api_key="test-abuseipdb-key", **cfg_overrides):
        from intel.abuseipdb import AbuseIPDBSource
        return AbuseIPDBSource(_make_source_cfg(**cfg_overrides), api_key=api_key)

    def test_fetch_returns_raw_indicators(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_RESPONSE)
            result = src.fetch()

        assert isinstance(result, list)
        assert len(result) == 3
        assert all(isinstance(r, RawIndicator) for r in result)

    def test_ip_addresses_correct(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_RESPONSE)
            result = src.fetch()

        ips = {r.ip for r in result}
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_confidence_scores_in_range(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_RESPONSE)
            result = src.fetch()

        for r in result:
            assert 0 <= r.source_confidence <= 100, f"Out-of-range score: {r.source_confidence}"

    def test_category_mapped_correctly(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_RESPONSE)
            result = src.fetch()

        # Entry 0 has category [18] = brute-force
        entry = next(r for r in result if r.ip == "1.2.3.4")
        assert entry.category == "brute-force"

    def test_missing_last_reported_defaults_gracefully(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_RESPONSE)
            result = src.fetch()

        entry = next(r for r in result if r.ip == "9.10.11.12")
        assert isinstance(entry.last_reported, datetime)

    def test_source_name_is_abuseipdb(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_RESPONSE)
            result = src.fetch()

        assert all(r.source == "abuseipdb" for r in result)

    def test_no_api_key_raises_source_fetch_error(self):
        src = self._make_source(api_key=None)
        with pytest.raises(SourceFetchError, match="API key"):
            src.fetch()

    def test_401_raises_source_fetch_error(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(401)
            with pytest.raises(SourceFetchError, match="401"):
                src.fetch()

    def test_429_raises_source_fetch_error(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(429)
            with pytest.raises(SourceFetchError, match="rate limit"):
                src.fetch()

    def test_network_error_raises_source_fetch_error(self):
        import requests as req_lib
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.side_effect = req_lib.RequestException("connection refused")
            with pytest.raises(SourceFetchError, match="network error"):
                src.fetch()

    def test_empty_data_returns_empty_list(self):
        src = self._make_source()
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"data": []})
            result = src.fetch()
        assert result == []

    def test_api_key_sent_in_header_not_url(self):
        """API key must travel via the Key header, never in the URL params."""
        src = self._make_source(api_key="SECRET-KEY")
        with patch("intel.abuseipdb.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"data": []})
            src.fetch()

        call_kwargs = mock_get.call_args
        # Check the URL itself does not contain the key
        url_arg = call_kwargs.args[0] if call_kwargs.args else call_kwargs.kwargs.get("url", "")
        params = call_kwargs.kwargs.get("params", {})
        headers = call_kwargs.kwargs.get("headers", {})
        assert "SECRET-KEY" not in url_arg
        assert headers.get("Key") == "SECRET-KEY", "API key must be in the Key header"
        assert "SECRET-KEY" not in str(params), "API key must NOT appear in query params"


# ═════════════════════════════════════════════════════════════════
# 3. OTXSource
# ═════════════════════════════════════════════════════════════════

class TestOTXSource:

    _SAMPLE_PULSE_RESPONSE = {
        "results": [
            {
                "id": "abc123",
                "name": "Malware C2 Botnet Campaign",
                "tags": ["malware", "c2", "botnet"],
                "adversary": "APT-99",
                "tlp": "amber",
                "pulse_sightings": 7,
                "modified": "2024-01-10T08:00:00Z",
                "created": "2024-01-08T10:00:00Z",
                "indicators": [
                    {"type": "IPv4", "indicator": "192.168.1.100", "created": "2024-01-10T00:00:00Z"},
                    {"type": "IPv4", "indicator": "10.20.30.40",   "created": "2024-01-10T01:00:00Z"},
                    {"type": "domain", "indicator": "evil.com",    "created": "2024-01-10T01:00:00Z"},  # not IPv4 — skip
                ],
            },
            {
                "id": "def456",
                "name": "SSH brute-force campaign",
                "tags": ["ssh", "brute-force"],
                "adversary": None,
                "tlp": "white",
                "pulse_sightings": 2,
                "modified": "2024-01-09T00:00:00Z",
                "created": "2024-01-09T00:00:00Z",
                "indicators": [
                    {"type": "IPv4", "indicator": "203.0.113.5", "created": "2024-01-09T00:00:00Z"},
                ],
            },
        ]
    }

    def _make_source(self, api_key="test-otx-key", **cfg_overrides):
        from intel.otx import OTXSource
        return OTXSource(_make_source_cfg(**cfg_overrides), api_key=api_key)

    def test_fetch_returns_raw_indicators(self):
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_PULSE_RESPONSE)
            result = src.fetch()

        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(r, RawIndicator) for r in result)

    def test_domain_indicators_filtered_out(self):
        """Non-IPv4 indicators (domain, URL, hash, etc.) must be excluded."""
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_PULSE_RESPONSE)
            result = src.fetch()

        assert all(r.ip != "evil.com" for r in result)

    def test_no_duplicate_ips_within_source(self):
        """If the same IP appears in two pulses, produce only one RawIndicator."""
        dup_response = {
            "results": [
                {
                    "id": "p1", "name": "pulse 1", "tags": [], "adversary": None,
                    "tlp": "white", "pulse_sightings": 0, "modified": "2024-01-01T00:00:00Z",
                    "indicators": [{"type": "IPv4", "indicator": "1.2.3.4", "created": "2024-01-01T00:00:00Z"}],
                },
                {
                    "id": "p2", "name": "pulse 2", "tags": [], "adversary": None,
                    "tlp": "white", "pulse_sightings": 0, "modified": "2024-01-02T00:00:00Z",
                    "indicators": [{"type": "IPv4", "indicator": "1.2.3.4", "created": "2024-01-02T00:00:00Z"}],
                },
            ]
        }
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, dup_response)
            result = src.fetch()

        ips = [r.ip for r in result if r.ip == "1.2.3.4"]
        assert len(ips) == 1, "Duplicate IPs within-source must be deduplicated"

    def test_source_name_is_otx(self):
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_PULSE_RESPONSE)
            result = src.fetch()

        assert all(r.source == "otx" for r in result)

    def test_confidence_high_for_adversary_amber_sightings(self):
        """The first pulse has adversary + AMBER + 7 sightings → score = 60+10+10+10 = 90."""
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_PULSE_RESPONSE)
            result = src.fetch()

        entry = next((r for r in result if r.ip == "192.168.1.100"), None)
        assert entry is not None
        assert entry.source_confidence == 90.0

    def test_confidence_base_for_no_enrichment(self):
        """Second pulse: no adversary, white TLP, <5 sightings → score = 60."""
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_PULSE_RESPONSE)
            result = src.fetch()

        entry = next((r for r in result if r.ip == "203.0.113.5"), None)
        assert entry is not None
        assert entry.source_confidence == 60.0

    def test_category_malware_c2_detected(self):
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_PULSE_RESPONSE)
            result = src.fetch()

        entry = next((r for r in result if r.ip == "192.168.1.100"), None)
        assert entry.category == "malware-c2"

    def test_category_brute_force_detected(self):
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, self._SAMPLE_PULSE_RESPONSE)
            result = src.fetch()

        entry = next((r for r in result if r.ip == "203.0.113.5"), None)
        assert entry.category == "brute-force"

    def test_no_api_key_raises(self):
        src = self._make_source(api_key=None)
        with pytest.raises(SourceFetchError, match="API key"):
            src.fetch()

    def test_403_raises_source_fetch_error(self):
        src = self._make_source()
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(403)
            with pytest.raises(SourceFetchError, match="403"):
                src.fetch()

    def test_api_key_in_header_not_url(self):
        src = self._make_source(api_key="OTX-SECRET")
        with patch("intel.otx.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, {"results": []})
            src.fetch()

        for call in mock_get.call_args_list:
            url = call.args[0] if call.args else call.kwargs.get("url", "")
            headers = call.kwargs.get("headers", {})
            assert "OTX-SECRET" not in url
            assert headers.get("X-OTX-API-KEY") == "OTX-SECRET"


# ═════════════════════════════════════════════════════════════════
# 4. SpamhausSource
# ═════════════════════════════════════════════════════════════════

class TestSpamhausSource:

    _SAMPLE_DROP = """\
; Spamhaus DROP List
; Last-Modified: Mon, 01 Jan 2024 00:00:00 UTC
;
1.2.3.0/24 ; SBL100
10.20.0.0/14 ; SBL200
192.0.2.0/24 ; SBL300
; end of list
"""

    _SAMPLE_EDROP = """\
; Spamhaus EDROP
198.51.100.0/24 ; ESBL1
203.0.113.0/24 ; ESBL2
"""

    def _make_source(self, **cfg_overrides):
        from intel.spamhaus import SpamhausSource
        return SpamhausSource(_make_source_cfg(**cfg_overrides), api_key=None)

    def _mock_both_lists(self, mock_get):
        """Set up mock_get to return different text per URL."""
        from intel.spamhaus import _DROP_URLS

        def side_effect(url, **kwargs):
            if "edrop" in url:
                return _mock_response(200, text=self._SAMPLE_EDROP)
            return _mock_response(200, text=self._SAMPLE_DROP)

        mock_get.side_effect = side_effect

    def test_fetch_returns_raw_indicators(self):
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()

        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(r, RawIndicator) for r in result)

    def test_cidr_blocks_parsed(self):
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()

        ips = {r.ip for r in result}
        assert "1.2.3.0/24" in ips
        assert "10.20.0.0/14" in ips
        assert "198.51.100.0/24" in ips

    def test_comments_excluded(self):
        """Lines starting with ; must not become indicators."""
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()

        for r in result:
            assert not r.ip.startswith(";")
            assert "Spamhaus" not in r.ip

    def test_no_duplicate_cidrs(self):
        """If DROP and EDROP happen to overlap, no IP should appear twice."""
        overlap_text = "1.2.3.0/24 ; SBL100\n"
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            mock_get.return_value = _mock_response(200, text=overlap_text)
            result = src.fetch()

        ips = [r.ip for r in result]
        assert len(ips) == len(set(ips)), "Duplicate CIDRs must be deduplicated"

    def test_source_name_is_spamhaus(self):
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()

        assert all(r.source == "spamhaus" for r in result)

    def test_confidence_is_80(self):
        """Spamhaus is a binary list — every entry must report confidence = 80."""
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()

        assert all(r.source_confidence == 80.0 for r in result)

    def test_category_is_spam(self):
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()

        assert all(r.category == "spam" for r in result)

    def test_no_api_key_required(self):
        """Spamhaus must work with api_key=None."""
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()
        assert len(result) > 0

    def test_network_error_raises(self):
        import requests as req_lib
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            mock_get.side_effect = req_lib.RequestException("timeout")
            with pytest.raises(SourceFetchError, match="network error"):
                src.fetch()

    def test_http_error_raises(self):
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            mock_get.return_value = _mock_response(503, text="Service Unavailable")
            with pytest.raises(SourceFetchError, match="503"):
                src.fetch()

    def test_last_reported_is_datetime(self):
        src = self._make_source()
        with patch("intel.spamhaus.requests.get") as mock_get:
            self._mock_both_lists(mock_get)
            result = src.fetch()

        assert all(isinstance(r.last_reported, datetime) for r in result)
