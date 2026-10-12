"""
enforcement/base_adapter.py — Abstract Base Class for enforcement adapters
==========================================================================
Strategy/Adapter pattern: LocalFirewallAdapter and AWSWAFAdapter
both implement this interface, making the orchestrator adapter-agnostic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseEnforcer(ABC):
    """
    Contract for a blocklist enforcement target.

    Sub-classes:
        local_firewall.LocalFirewallAdapter   ← PRIMARY (fully implemented)
        aws_waf.AWSWAFAdapter                 ← OPTIONAL (costs money; see docs)
    """

    def __init__(self, enforcement_cfg: dict) -> None:
        self.cfg = enforcement_cfg

    @abstractmethod
    def add(self, ips: list[str]) -> int:
        """
        Add the given IP/CIDR strings to the enforcement point.

        Args:
            ips: List of IP or CIDR strings, e.g. ["1.2.3.4", "10.0.0.0/8"].

        Returns:
            Number of IPs actually added (0 if already present / dry-run).
        """

    @abstractmethod
    def remove(self, ips: list[str]) -> int:
        """
        Remove the given IPs from the enforcement point.

        Returns:
            Number of IPs actually removed.
        """

    @abstractmethod
    def current_set(self) -> set[str]:
        """
        Return the full set of IPs currently in the enforcement point.
        Used to diff what needs to be added/removed each run.
        """

    def is_enabled(self) -> bool:
        return bool(self.cfg.get("enabled", False))

    def is_dry_run(self) -> bool:
        return bool(self.cfg.get("dry_run", False))


class EnforcerError(Exception):
    """Raised when an enforcement operation fails."""
