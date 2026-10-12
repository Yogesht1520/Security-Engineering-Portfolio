"""
intel/base_source.py — Abstract Base Class for all threat intel sources
========================================================================
Every source module must implement this interface.
The orchestrator in main.py uses duck-typing/ABC to call .fetch() uniformly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from models import RawIndicator


class BaseIntelSource(ABC):
    """
    Contract for a threat intelligence feed.

    Sub-classes:
        abuseipdb.AbuseIPDBSource
        otx.OTXSource
        spamhaus.SpamhausSource
    """

    #: Human-readable source identifier (used in RawIndicator.source)
    SOURCE_NAME: str = ""

    def __init__(self, source_cfg: dict, api_key: str | None = None) -> None:
        """
        Args:
            source_cfg: The source-specific block from config.yaml (e.g. cfg["sources"]["abuseipdb"]).
            api_key:    API key for authenticated sources; None for key-free sources like Spamhaus.
        """
        self.cfg = source_cfg
        self.api_key = api_key

    @abstractmethod
    def fetch(self) -> list[RawIndicator]:
        """
        Pull indicators from this source and return them as RawIndicator objects.

        Returns:
            A list of RawIndicator instances. Empty list if nothing retrieved.
            Must be idempotent — calling twice should not produce duplicates in storage.

        Raises:
            SourceFetchError: on unrecoverable network/auth failures (sub-classes raise this).
        """

    def is_enabled(self) -> bool:
        """Return True if this source is enabled in the config."""
        return bool(self.cfg.get("enabled", False))


class SourceFetchError(Exception):
    """Raised when a source fails to fetch data (network error, auth failure, etc.)."""
