"""
intel/spamhaus.py — Spamhaus DROP / EDROP Threat Intelligence Source
=====================================================================
Spamhaus DROP (Don't Route Or Peer) and EDROP (Extended DROP) lists are
publicly available plaintext files listing IP ranges used by professional
spam/cybercrime operations.

Free-tier notes:
  - No API key required.
  - No daily rate limit (plain HTTP text files, mirrored by Spamhaus).
  - Lists are updated ~daily; fetching once per 6-hour run is well within
    acceptable use. Spamhaus TOS requests no >20 req/day per source IP.

Confidence derivation:
  DROP/EDROP are highly curated, low-false-positive lists (binary yes/no).
  We treat every entry as source_confidence = 80 (high but not 100 —
  leaves room for the scoring engine's multi-source bonus).

Docs: https://www.spamhaus.org/drop/
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import requests

from intel.base_source import BaseIntelSource, SourceFetchError
from models import RawIndicator

logger = logging.getLogger(__name__)

_DROP_URLS: dict[str, str] = {
    "drop":  "https://www.spamhaus.org/drop/drop.txt",
    "edrop": "https://www.spamhaus.org/drop/edrop.txt",
}

# Matches a CIDR block at the start of a line, e.g. "1.2.3.0/24 ; SBL12345"
_CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")

_SOURCE_CONFIDENCE = 80.0  # binary list — high confidence, leave bonus headroom


class SpamhausSource(BaseIntelSource):
    """
    Fetches Spamhaus DROP and EDROP plaintext blocklists.
    No API key needed — api_key parameter is accepted but ignored.
    """

    SOURCE_NAME = "spamhaus"

    def fetch(self) -> list[RawIndicator]:
        indicators: list[RawIndicator] = []
        seen: set[str] = set()
        fetch_time = datetime.now(timezone.utc)

        for list_name, url in _DROP_URLS.items():
            logger.info("[Spamhaus] Fetching %s from %s", list_name.upper(), url)
            text = self._fetch_text(url)
            count_before = len(indicators)

            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue  # skip comments and blank lines
                match = _CIDR_RE.match(line)
                if not match:
                    continue
                cidr = match.group(1)
                if cidr in seen:
                    continue
                seen.add(cidr)
                indicators.append(
                    RawIndicator(
                        ip=cidr,
                        source=self.SOURCE_NAME,
                        source_confidence=_SOURCE_CONFIDENCE,
                        category="spam",  # all Spamhaus DROP entries are spam/cybercrime netblocks
                        last_reported=fetch_time,
                    )
                )

            logger.info(
                "[Spamhaus] %s: parsed %d CIDRs",
                list_name.upper(),
                len(indicators) - count_before,
            )

        logger.info("[Spamhaus] Total RawIndicators: %d", len(indicators))
        return indicators

    # ── private ──────────────────────────────────────────────────────────────

    @staticmethod
    def _fetch_text(url: str) -> str:
        """Download a plaintext Spamhaus list, raising SourceFetchError on failure."""
        try:
            resp = requests.get(url, timeout=30)
        except requests.RequestException as exc:
            raise SourceFetchError(f"Spamhaus network error ({url}): {exc}") from exc

        if not resp.ok:
            raise SourceFetchError(
                f"Spamhaus returned HTTP {resp.status_code} from {url}: {resp.text[:200]}"
            )
        return resp.text
