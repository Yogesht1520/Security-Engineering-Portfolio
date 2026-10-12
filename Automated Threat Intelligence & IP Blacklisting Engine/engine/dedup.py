"""
engine/dedup.py — Deduplication logic for threat indicators
===========================================================
Groups raw threat indicators by IP/CIDR and ensures within-source duplicates
retain only the highest confidence indicator per source.
"""
from __future__ import annotations

from models import RawIndicator


def deduplicate(indicators: list[RawIndicator]) -> dict[str, list[RawIndicator]]:
    """
    Group indicators by IP address or CIDR notation.

    Returns:
        dict mapping IP/CIDR string to list of RawIndicators (one per unique source).
        If the same source reported an IP multiple times, only the highest confidence
        indicator for that source is kept.
    """
    if not indicators:
        return {}

    # ip -> {source: highest_confidence_indicator}
    grouped: dict[str, dict[str, RawIndicator]] = {}

    for ind in indicators:
        ip = ind.ip.strip()
        if not ip:
            continue
        if ip not in grouped:
            grouped[ip] = {}

        src = ind.source
        if src not in grouped[ip] or ind.source_confidence > grouped[ip][src].source_confidence:
            grouped[ip][src] = ind

    return {ip: list(sources.values()) for ip, sources in grouped.items()}
