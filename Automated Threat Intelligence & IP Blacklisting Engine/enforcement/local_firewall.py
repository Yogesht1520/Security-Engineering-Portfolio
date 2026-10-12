"""
enforcement/local_firewall.py — Linux ipset firewall enforcement adapter
========================================================================
Primary enforcement adapter: manages a Linux kernel ipset hash:net set
for fast, zero-cloud-cost blocking. Supports dry-run execution on Windows/dev.
"""
from __future__ import annotations

import logging
import subprocess

from enforcement.base_adapter import BaseEnforcer, EnforcerError

logger = logging.getLogger(__name__)


class LocalFirewallAdapter(BaseEnforcer):
    """
    Manages an ipset hash:net set for IP/CIDR blocking.
    Primary enforcement adapter — fully implemented, no cloud cost.
    """

    def __init__(self, enforcement_cfg: dict) -> None:
        super().__init__(enforcement_cfg)
        self.ipset_name = enforcement_cfg.get("ipset_name", "threat-intel-blocklist")
        self.ipset_type = enforcement_cfg.get("ipset_type", "hash:net")

    def _run_ipset(self, *args: str, capture: bool = False) -> str:
        """
        Execute an ipset command.
        In dry_run mode: logs the command and returns empty string without calling subprocess.
        """
        if self.is_dry_run():
            logger.info("[DRY-RUN] ipset %s", " ".join(args))
            return ""

        cmd = ["ipset", *args]
        try:
            res = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
            return res.stdout if capture else ""
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else str(exc)
            logger.error("ipset command failed: %s — %s", " ".join(cmd), stderr)
            raise EnforcerError(f"ipset command failed: {stderr}") from exc
        except (FileNotFoundError, OSError) as exc:
            logger.error("ipset command not available or failed: %s", exc)
            raise EnforcerError(f"ipset command failed: {exc}") from exc

    def ensure_set_exists(self) -> None:
        """ipset create <name> hash:net -exist — idempotent."""
        self._run_ipset("create", self.ipset_name, self.ipset_type, "-exist")

    def add(self, ips: list[str]) -> int:
        """
        Add each IP/CIDR to the ipset.
        Returns count actually added.
        """
        if not ips:
            return 0

        self.ensure_set_exists()

        count = 0
        for ip in ips:
            self._run_ipset("add", self.ipset_name, ip)
            count += 1
        return count

    def remove(self, ips: list[str]) -> int:
        """
        Remove each IP/CIDR from the ipset.
        Returns count actually removed.
        """
        if not ips:
            return 0

        count = 0
        for ip in ips:
            self._run_ipset("del", self.ipset_name, ip)
            count += 1
        return count

    def current_set(self) -> set[str]:
        """
        Parse `ipset list <name>` output to get the set of current entries.
        Returns empty set in dry_run mode (no kernel read).
        """
        if self.is_dry_run():
            return set()

        output = self._run_ipset("list", self.ipset_name, capture=True)
        members: set[str] = set()
        in_members = False
        for line in output.splitlines():
            stripped = line.strip()
            if stripped == "Members:":
                in_members = True
                continue
            if in_members and stripped:
                members.add(stripped)
        return members
