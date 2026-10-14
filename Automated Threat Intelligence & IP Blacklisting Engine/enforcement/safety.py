"""
enforcement/safety.py — Safety circuit breakers and change-rate guardrails
===========================================================================
Protects against automated catastrophic failure:
- Hard cap on maximum additions / removals per run
- Percentage-based volatility thresholds (e.g. abort if >20% of blocklist changes)
- Strict validation ensuring no protected/allowlisted IPs reach enforcement targets
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from engine.validator import is_protected_network, parse_ip_or_network

logger = logging.getLogger(__name__)


class CircuitBreakerError(Exception):
    """Raised when an automated change exceeds safety thresholds."""


@dataclass
class GuardrailConfig:
    max_changes_per_run: int = 500
    max_change_percentage: float = 0.20  # 20%
    min_size_for_percentage_check: int = 20
    custom_allowlist: list[str] | None = None


class SafetyController:
    """Enforces safety guardrails prior to executing firewall state mutations."""

    def __init__(self, config: GuardrailConfig | None = None) -> None:
        self.cfg = config or GuardrailConfig()

    def filter_safe_ips(self, ips: list[str]) -> tuple[list[str], list[str]]:
        """
        Filter out any protected, private, loopback, or allowlisted IPs.

        Returns:
            (safe_ips, blocked_protected_ips)
        """
        safe: list[str] = []
        protected: list[str] = []

        for ip in ips:
            parsed = parse_ip_or_network(ip)
            if parsed is None:
                protected.append(ip)
                continue

            is_prot, reason = is_protected_network(parsed, self.cfg.custom_allowlist)
            if is_prot:
                logger.warning("SAFETY GUARD: Blocked attempt to enforce protected target '%s' (%s)", ip, reason)
                protected.append(ip)
            else:
                safe.append(str(parsed))

        return safe, protected

    def verify_rate_of_change(
        self,
        current_active_count: int,
        to_add_count: int,
        to_remove_count: int,
        force: bool = False,
    ) -> None:
        """
        Verify that additions and removals do not exceed safety circuit breakers.
        Raises CircuitBreakerError if limit exceeded unless force=True.
        """
        total_changes = to_add_count + to_remove_count

        # 1. Absolute count limit check
        if total_changes > self.cfg.max_changes_per_run:
            msg = (
                f"Rate-of-change circuit breaker: Total planned changes ({total_changes}: "
                f"+{to_add_count}/-{to_remove_count}) exceeds max_changes_per_run "
                f"({self.cfg.max_changes_per_run})."
            )
            if force:
                logger.warning("[FORCE OVERRIDE] %s Executing anyway.", msg)
            else:
                logger.error("[CIRCUIT BREAKER TRIGGERED] %s Run halted.", msg)
                raise CircuitBreakerError(msg)

        # 2. Percentage check
        if current_active_count >= self.cfg.min_size_for_percentage_check:
            ratio = total_changes / float(current_active_count)
            if ratio > self.cfg.max_change_percentage:
                msg = (
                    f"Volatility circuit breaker: Planned changes ({total_changes}) represent "
                    f"{ratio * 100:.1f}% of active blocklist ({current_active_count}), exceeding "
                    f"maximum allowed {self.cfg.max_change_percentage * 100:.1f}%."
                )
                if force:
                    logger.warning("[FORCE OVERRIDE] %s Executing anyway.", msg)
                else:
                    logger.error("[CIRCUIT BREAKER TRIGGERED] %s Run halted.", msg)
                    raise CircuitBreakerError(msg)
