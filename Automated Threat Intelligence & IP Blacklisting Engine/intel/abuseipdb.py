"""
intel/abuseipdb.py — AbuseIPDB Threat Intelligence Source
==========================================================
Free-tier limits (as of 2024):
  - 1,000 API checks/day
  - /blacklist endpoint: returns up to 10,000 IPs at confidenceMinimum >= 25
    (we filter further by min_confidence from config)
  - Rate-limit header: X-RateLimit-Remaining / X-RateLimit-Reset

Docs: https://docs.abuseipdb.com/#blacklist-endpoint
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from intel.base_source import BaseIntelSource, SourceFetchError
from models import RawIndicator

logger = logging.getLogger(__name__)

# AbuseIPDB category ID → human-readable label mapping (subset of common ones)
# Full list: https://www.abuseipdb.com/categories
_CATEGORY_MAP: dict[int, str] = {
    1:  "dns-compromise",
    2:  "dns-poisoning",
    3:  "fraud-orders",
    4:  "ddos-attack",
    5:  "ftp-brute-force",
    6:  "ping-of-death",
    7:  "phishing",
    8:  "fraud-voip",
    9:  "open-proxy",
    10: "web-spam",
    11: "email-spam",
    12: "blog-spam",
    13: "vpn-ip",
    14: "port-scan",
    15: "hacking",
    16: "sql-injection",
    17: "spoofing",
    18: "brute-force",
    19: "bad-web-bot",
    20: "exploited-host",
    21: "web-app-attack",
    22: "ssh-brute-force",
    23: "iot-targeted",
}

_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"


class AbuseIPDBSource(BaseIntelSource):
    """Fetches the AbuseIPDB blacklist via the /blacklist endpoint."""

    SOURCE_NAME = "abuseipdb"

    def fetch(self) -> list[RawIndicator]:
        if not self.api_key:
            raise SourceFetchError(
                "AbuseIPDB API key is missing. Set api_keys.abuseipdb in config.yaml "
                "or via TIBL_API_KEYS__ABUSEIPDB env var."
            )

        limit = self.cfg.get("limit", 500)
        max_age = self.cfg.get("max_age_days", 30)
        min_confidence = self.cfg.get("min_confidence", 50)

        params = {
            "confidenceMinimum": min_confidence,
            "limit": limit,
            "maxAgeInDays": max_age,
        }
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

        logger.info(
            "[AbuseIPDB] Fetching blacklist — limit=%d, maxAge=%d days, minConfidence=%d",
            limit, max_age, min_confidence,
        )

        try:
            resp = requests.get(
                _BLACKLIST_URL,
                params=params,
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise SourceFetchError(f"AbuseIPDB network error: {exc}") from exc

        # Expose remaining quota in logs for awareness
        remaining = resp.headers.get("X-RateLimit-Remaining", "?")
        logger.debug("[AbuseIPDB] Rate-limit remaining: %s", remaining)

        if resp.status_code == 401:
            raise SourceFetchError(
                "AbuseIPDB returned 401 Unauthorized — check your API key."
            )
        if resp.status_code == 429:
            raise SourceFetchError(
                "AbuseIPDB rate limit exceeded (1,000 checks/day on free tier). "
                "Try again tomorrow or reduce run frequency."
            )
        if not resp.ok:
            raise SourceFetchError(
                f"AbuseIPDB returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        data = resp.json()
        entries = data.get("data", [])
        logger.info("[AbuseIPDB] Retrieved %d entries from API", len(entries))

        indicators: list[RawIndicator] = []
        for entry in entries:
            ip = entry.get("ipAddress", "").strip()
            if not ip:
                continue

            # abuseConfidenceScore is 0–100 — use directly as source_confidence
            score = float(entry.get("abuseConfidenceScore", 0))

            # Map the first category ID to a label; fall back to "unknown"
            raw_categories: list[int] = entry.get("categories", [])
            category = _CATEGORY_MAP.get(raw_categories[0], "unknown") if raw_categories else "unknown"

            # lastReportedAt may be None for brand-new entries
            last_reported_str: str | None = entry.get("lastReportedAt")
            if last_reported_str:
                try:
                    last_reported = datetime.fromisoformat(
                        last_reported_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    last_reported = datetime.now(timezone.utc)
            else:
                last_reported = datetime.now(timezone.utc)

            indicators.append(
                RawIndicator(
                    ip=ip,
                    source=self.SOURCE_NAME,
                    source_confidence=score,
                    category=category,
                    last_reported=last_reported,
                )
            )

        logger.info("[AbuseIPDB] Produced %d RawIndicators", len(indicators))
        return indicators
