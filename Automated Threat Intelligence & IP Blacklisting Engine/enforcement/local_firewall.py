"""
enforcement/local_firewall.py — Linux ipset firewall enforcement adapter with IPv4/IPv6 support
================================================================================================
Primary enforcement adapter: manages Linux kernel ipset hash:net sets
for fast, zero-cloud-cost blocking. Supports dual-stack (IPv4 & IPv6)
and dry-run execution on Windows/dev environments.
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
    Supports dual-stack IPv4 (family inet) and IPv6 (family inet6).
    """

    def __init__(self, enforcement_cfg: dict) -> None:
        super().__init__(enforcement_cfg)
        self.ipset_name = enforcement_cfg.get("ipset_name", "threat-intel-blocklist")
        self.ipset_name_v6 = enforcement_cfg.get("ipset_name_v6", f"{self.ipset_name}-v6")
        self.ipset_type = enforcement_cfg.get("ipset_type", "hash:net")
        self._v6_initialized = False

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

    def ensure_set_exists(self, v6: bool = False) -> None:
        """ipset create <name> hash:net -exist — idempotent."""
        if v6:
            self._run_ipset("create", self.ipset_name_v6, self.ipset_type, "family", "inet6", "-exist")
            self._v6_initialized = True
        else:
            self._run_ipset("create", self.ipset_name, self.ipset_type, "-exist")

    def _target_set_for(self, ip: str) -> str:
        if ":" in ip:
            if not self._v6_initialized and not self.is_dry_run():
                try:
                    self.ensure_set_exists(v6=True)
                except Exception as exc:
                    logger.debug("Failed to ensure IPv6 set exists: %s", exc)
            return self.ipset_name_v6
        return self.ipset_name

    def add(self, ips: list[str]) -> int:
        """
        Add each IP/CIDR to the corresponding IPv4 or IPv6 ipset.
        Returns count actually added.
        """
        if not ips:
            return 0

        self.ensure_set_exists()

        count = 0
        for ip in ips:
            target_set = self._target_set_for(ip)
            self._run_ipset("add", target_set, ip)
            count += 1
        return count

    def remove(self, ips: list[str]) -> int:
        """
        Remove each IP/CIDR from the corresponding IPv4 or IPv6 ipset.
        Returns count actually removed.
        """
        if not ips:
            return 0

        count = 0
        for ip in ips:
            target_set = self._target_set_for(ip)
            self._run_ipset("del", target_set, ip)
            count += 1
        return count

    def _parse_members(self, output: str) -> set[str]:
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

    def current_set(self) -> set[str]:
        """
        Parse `ipset list <name>` output to get the set of current entries.
        Returns empty set in dry_run mode (no kernel read).
        Combines IPv4 and IPv6 entries if both sets exist.
        """
        if self.is_dry_run():
            return set()

        members: set[str] = set()
        try:
            output_v4 = self._run_ipset("list", self.ipset_name, capture=True)
            members.update(self._parse_members(output_v4))
        except Exception as exc:
            logger.debug("Could not read IPv4 set %s: %s", self.ipset_name, exc)

        try:
            output_v6 = self._run_ipset("list", self.ipset_name_v6, capture=True)
            members.update(self._parse_members(output_v6))
        except Exception:
            # v6 set may not be created yet if no IPv6 indicators were seen
            pass

        return members
