"""
intel/otx.py — AlienVault OTX Threat Intelligence Source
=========================================================
Free-tier notes:
  - No strict daily request cap (generous limits).
  - We fetch recent public pulses that contain IPv4 indicators.
  - OTX does not expose a per-IP confidence score; we derive one from
    the pulse's adversary_score / TLP / sighting count.

Docs: https://otx.alienvault.com/api
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from intel.base_source import BaseIntelSource, SourceFetchError
from models import RawIndicator

logger = logging.getLogger(__name__)

_OTX_BASE = "https://otx.alienvault.com/api/v1"
_SUBSCRIBED_PULSES_URL = f"{_OTX_BASE}/pulses/subscribed"
_RECENT_PULSES_URL = f"{_OTX_BASE}/pulses/activity"


class OTXSource(BaseIntelSource):
    """
    Fetches IPv4 indicators from AlienVault OTX pulse activity feed.

    Confidence derivation:
      OTX pulses have no per-IP score, so we synthesise one:
        base = 60 (mid-range for a public community feed)
        +10 if the pulse has a tagged adversary
        +10 if TLP is RED or AMBER (vetted/restricted = more reliable)
        +10 if pulse has ≥5 pulse_sightings  (corroborated)
      Capped at 95 to leave room for multi-source bonus.
    """

    SOURCE_NAME = "otx"

    def fetch(self) -> list[RawIndicator]:
        if not self.api_key:
            raise SourceFetchError(
                "OTX API key is missing. Set api_keys.otx in config.yaml "
                "or via TIBL_API_KEYS__OTX env var."
            )

        pulse_limit = self.cfg.get("pulse_limit", 20)
        headers = {"X-OTX-API-KEY": self.api_key}

        logger.info("[OTX] Fetching up to %d recent pulses …", pulse_limit)

        # Pull subscribed + activity pulses for breadth
        pulses: list[dict] = []
        for url in (_SUBSCRIBED_PULSES_URL, _RECENT_PULSES_URL):
            try:
                resp = requests.get(
                    url,
                    params={"limit": pulse_limit},
                    headers=headers,
                    timeout=30,
                )
            except requests.RequestException as exc:
                raise SourceFetchError(f"OTX network error ({url}): {exc}") from exc

            if resp.status_code == 403:
                raise SourceFetchError(
                    "OTX returned 403 Forbidden — check your API key."
                )
            if not resp.ok:
                raise SourceFetchError(
                    f"OTX returned HTTP {resp.status_code} from {url}: {resp.text[:200]}"
                )

            batch = resp.json().get("results", [])
            pulses.extend(batch)
            logger.debug("[OTX] %s — %d pulses received", url, len(batch))

        logger.info("[OTX] Total pulses to process: %d", len(pulses))

        indicators: list[RawIndicator] = []
        seen_ips: set[str] = set()  # dedup within-source before cross-source dedup

        for pulse in pulses:
            confidence = self._derive_confidence(pulse)
            category = self._derive_category(pulse)

            # Parse pulse modified timestamp
            modified_str: str = pulse.get("modified", "") or pulse.get("created", "")
            last_reported = _parse_otx_ts(modified_str)

            # Extract IPv4 indicators embedded in the pulse
            for indicator in pulse.get("indicators", []):
                if indicator.get("type") not in ("IPv4", "IPv4-CIDR"):
                    continue
                ip = indicator.get("indicator", "").strip()
                if not ip or ip in seen_ips:
                    continue
                seen_ips.add(ip)

                # Use indicator-level expiration if available to override last_reported
                ind_created = _parse_otx_ts(indicator.get("created", ""))
                indicators.append(
                    RawIndicator(
                        ip=ip,
                        source=self.SOURCE_NAME,
                        source_confidence=confidence,
                        category=category,
                        last_reported=ind_created or last_reported,
                    )
                )

        logger.info("[OTX] Produced %d unique RawIndicators", len(indicators))
        return indicators

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _derive_confidence(pulse: dict) -> float:
        """Synthesise a 0–100 confidence score from pulse metadata."""
        score: float = 60.0
        if pulse.get("adversary"):            # named threat actor attributed
            score += 10
        tlp: str = (pulse.get("tlp") or "").upper()
        if tlp in ("RED", "AMBER"):           # restricted/vetted = more reliable
            score += 10
        if (pulse.get("pulse_sightings") or 0) >= 5:
            score += 10
        return min(score, 95.0)

    @staticmethod
    def _derive_category(pulse: dict) -> str:
        """Map OTX pulse tags / name to a coarse category."""
        tags: list[str] = [t.lower() for t in (pulse.get("tags") or [])]
        name: str = (pulse.get("name") or "").lower()
        combined = " ".join(tags) + " " + name

        if any(k in combined for k in ("malware", "c2", "command", "control", "botnet")):
            return "malware-c2"
        if any(k in combined for k in ("brute", "credential", "login", "ssh", "rdp")):
            return "brute-force"
        if any(k in combined for k in ("phish", "fraud", "scam")):
            return "phishing"
        if any(k in combined for k in ("scan", "reconnaissance", "recon", "probe")):
            return "port-scan"
        if any(k in combined for k in ("spam", "email")):
            return "spam"
        if any(k in combined for k in ("ddos", "dos", "flood")):
            return "ddos-attack"
        if any(k in combined for k in ("exploit", "vuln", "cve")):
            return "web-app-attack"
        return "unknown"


def _parse_otx_ts(ts_str: str) -> datetime:
    """Parse an OTX ISO-8601 timestamp, falling back to utcnow on failure."""
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
