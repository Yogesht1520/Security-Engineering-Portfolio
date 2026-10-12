"""
enforcement/aws_waf.py — AWS WAF IPSet enforcement adapter
===========================================================
OPTIONAL secondary adapter for synchronizing blacklisted IPs to an AWS WAF IPSet.
Note: Incurs AWS costs (~$1/month per IPSet + WAF request fees).
Disabled by default. Emits a visible cost warning whenever initialized.
"""
from __future__ import annotations

import logging
from typing import Any

from enforcement.base_adapter import BaseEnforcer, EnforcerError

logger = logging.getLogger(__name__)

_AWS_COST_NOTICE = (
    "AWS WAF IP set ENABLED. "
    "Cost: ~$1/month per IP set + $0.60/million WAF requests. "
    "Set enforcement.aws_waf.enabled: false in config.yaml to suppress this. "
    "See: https://aws.amazon.com/waf/pricing/"
)


def _normalize_cidr(ip: str) -> str:
    """Convert bare IP to /32 CIDR for WAF compatibility."""
    return ip if "/" in ip else f"{ip}/32"


class AWSWAFAdapter(BaseEnforcer):
    """
    OPTIONAL secondary enforcement adapter — AWS WAF IP set via boto3.
    Incurs AWS costs. Must be explicitly enabled in config.yaml.
    """

    def __init__(self, enforcement_cfg: dict) -> None:
        super().__init__(enforcement_cfg)
        logging.getLogger(__name__).warning(_AWS_COST_NOTICE)
        self.region = enforcement_cfg.get("region", "us-east-1")
        self.ip_set_name = enforcement_cfg.get("ip_set_name", "threat-intel-blocklist")
        self.ip_set_id = enforcement_cfg.get("ip_set_id", "")
        self.scope = enforcement_cfg.get("scope", "REGIONAL")

    def _get_client(self) -> Any:
        """Lazily load boto3 and initialize WAFv2 client with validation."""
        try:
            import boto3
        except ImportError as exc:
            raise EnforcerError("boto3 not installed. Run: pip install boto3") from exc

        if not self.ip_set_id:
            raise EnforcerError("ip_set_id must be configured for AWS WAF")

        return boto3.client("wafv2", region_name=self.region)

    def add(self, ips: list[str]) -> int:
        """
        Add IP/CIDR entries to AWS WAF IP set.
        Normalizes IPs to /32 CIDR notation.
        """
        if not ips:
            return 0

        if self.is_dry_run():
            logger.info("[DRY-RUN] AWS WAF add: %d IPs", len(ips))
            return len(ips)

        client = self._get_client()
        try:
            response = client.get_ip_set(
                Name=self.ip_set_name,
                Scope=self.scope,
                Id=self.ip_set_id,
            )
            lock_token = response.get("LockToken", "")
            existing_addresses = set(response.get("IPSet", {}).get("Addresses", []))
            normalized_to_add = {_normalize_cidr(ip) for ip in ips}
            new_addresses = existing_addresses.union(normalized_to_add)

            client.update_ip_set(
                Name=self.ip_set_name,
                Scope=self.scope,
                Id=self.ip_set_id,
                Addresses=sorted(list(new_addresses)),
                LockToken=lock_token,
            )
            return len(new_addresses - existing_addresses)
        except EnforcerError:
            raise
        except Exception as exc:
            raise EnforcerError(f"AWS WAF update failed: {exc}") from exc

    def remove(self, ips: list[str]) -> int:
        """Remove IP/CIDR entries from AWS WAF IP set."""
        if not ips:
            return 0

        if self.is_dry_run():
            logger.info("[DRY-RUN] AWS WAF remove: %d IPs", len(ips))
            return len(ips)

        client = self._get_client()
        try:
            response = client.get_ip_set(
                Name=self.ip_set_name,
                Scope=self.scope,
                Id=self.ip_set_id,
            )
            lock_token = response.get("LockToken", "")
            existing_addresses = set(response.get("IPSet", {}).get("Addresses", []))
            to_remove = {_normalize_cidr(ip) for ip in ips}
            remaining_addresses = existing_addresses - to_remove

            client.update_ip_set(
                Name=self.ip_set_name,
                Scope=self.scope,
                Id=self.ip_set_id,
                Addresses=sorted(list(remaining_addresses)),
                LockToken=lock_token,
            )
            return len(existing_addresses.intersection(to_remove))
        except EnforcerError:
            raise
        except Exception as exc:
            raise EnforcerError(f"AWS WAF remove failed: {exc}") from exc

    def current_set(self) -> set[str]:
        """Fetch current member addresses in the AWS WAF IP set."""
        if self.is_dry_run():
            return set()

        client = self._get_client()
        try:
            response = client.get_ip_set(
                Name=self.ip_set_name,
                Scope=self.scope,
                Id=self.ip_set_id,
            )
            return set(response.get("IPSet", {}).get("Addresses", []))
        except EnforcerError:
            raise
        except Exception as exc:
            raise EnforcerError(f"AWS WAF get_ip_set failed: {exc}") from exc
