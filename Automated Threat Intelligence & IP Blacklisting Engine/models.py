"""
models.py — shared data-model dataclasses
==========================================
Defined here (not in sub-packages) so all modules can import without
creating circular dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class RawIndicator:
    """A single IP threat report as returned by one intel source."""
    ip: str
    source: str                     # "abuseipdb" | "otx" | "spamhaus"
    source_confidence: float        # 0–100, normalised per-source
    category: str                   # e.g. "brute-force", "spam", "malware-c2"
    last_reported: datetime
    upstream_lineage: list[str] = field(default_factory=list)


@dataclass
class ScoredIP:
    """
    Deduplicated + scored IP — one record per unique IP, combining
    all sources that flagged it with full evidence and lifecycle tracking.
    """
    ip: str
    combined_score: float           # weighted avg across sources + multi-source bonus
    sources: list[str] = field(default_factory=list)
    category: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: list[dict[str, Any]] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    ip_version: int = 4
