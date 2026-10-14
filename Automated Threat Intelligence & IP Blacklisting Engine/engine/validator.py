"""
engine/validator.py — IP/IPv6 validation and bogon defense
===========================================================
Validates threat indicators using Python's standard `ipaddress` module.
Defends against upstream poisoning and misclassifications by rejecting:
  - Custom user-configured allowlist IPs and CIDR subnets
  - Loopback addresses (127.0.0.0/8, ::1)
  - RFC 1918 & RFC 4193 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
  - Link-local addresses (169.254.0.0/16, fe80::/10)
  - Multicast addresses (224.0.0.0/4, ff00::/8)
  - Unspecified / default route addresses (0.0.0.0, ::)
  - Reserved addresses (e.g. 240.0.0.0/4)
"""
from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from models import RawIndicator

logger = logging.getLogger(__name__)

IPAddressOrNetwork = (
    ipaddress.IPv4Address
    | ipaddress.IPv6Address
    | ipaddress.IPv4Network
    | ipaddress.IPv6Network
)

# Explicit RFC 1918 & RFC 4193 Private Ranges
# (Avoids python's ip.is_private classifying RFC 5737 / RFC 3849 documentation test IPs as private)
PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def parse_ip_or_network(target: str) -> IPAddressOrNetwork | None:
    """
    Parse an IP address or CIDR network string safely.
    Returns an IPv4/IPv6 address or network object, or None if invalid.
    """
    if not target or not isinstance(target, str):
        return None

    cleaned = target.strip()
    if not cleaned:
        return None

    # First attempt single IP
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass

    # Next attempt CIDR network
    try:
        return ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        pass

    return None


def _is_rfc1918_private(obj: IPAddressOrNetwork) -> bool:
    """Check whether IP or network falls strictly within RFC 1918 / RFC 4193 private space."""
    for priv_net in PRIVATE_NETWORKS:
        if obj.version != priv_net.version:
            continue
        if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if obj in priv_net:
                return True
        elif isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if obj.subnet_of(priv_net) or priv_net.subnet_of(obj) or obj.overlaps(priv_net):
                return True
    return False


def is_protected_network(
    obj: IPAddressOrNetwork | str,
    custom_allowlist: list[str] | None = None,
) -> tuple[bool, str]:
    """
    Check whether an IP address or network belongs to a protected range:
    custom allowlist, loopback, private RFC1918, link-local, multicast,
    reserved, or unspecified.

    Returns:
        (is_protected, reason)
    """
    if isinstance(obj, str):
        parsed = parse_ip_or_network(obj)
        if parsed is None:
            return True, f"Invalid IP/network syntax: {obj}"
    else:
        parsed = obj

    if parsed is None:
        return True, "None or empty target"

    # 1. Custom allowlist check takes first precedence
    if custom_allowlist:
        for entry in custom_allowlist:
            if not entry:
                continue
            allow_obj = parse_ip_or_network(entry)
            if allow_obj is None:
                continue

            # Compare IP to IP or Network
            if isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                if isinstance(allow_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if parsed == allow_obj:
                        return True, f"Target matched user allowlist: {entry}"
                elif isinstance(allow_obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if parsed.version == allow_obj.version and parsed in allow_obj:
                        return True, f"Target matched user allowlist: {entry}"

            # Compare Network to IP or Network
            elif isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if isinstance(allow_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if parsed.version == allow_obj.version and allow_obj in parsed:
                        return True, f"Target matched user allowlist: {entry}"
                elif isinstance(allow_obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if parsed.version == allow_obj.version and (
                        parsed.subnet_of(allow_obj)
                        or allow_obj.subnet_of(parsed)
                        or parsed.overlaps(allow_obj)
                    ):
                        return True, f"Target matched user allowlist: {entry}"

    # 2. Loopback
    if parsed.is_loopback:
        return True, f"Forbidden loopback address/range: {parsed}"

    # 3. Private / RFC 1918 / RFC 4193
    if _is_rfc1918_private(parsed):
        return True, f"Forbidden private/RFC1918 address/range: {parsed}"

    # 4. Link-local (e.g. AWS IMDS 169.254.169.254, fe80::/10)
    if parsed.is_link_local:
        return True, f"Forbidden link-local address/range: {parsed}"

    # 5. Multicast
    if parsed.is_multicast:
        return True, f"Forbidden multicast address/range: {parsed}"

    # 6. Reserved (e.g. 240.0.0.0/4)
    if parsed.is_reserved:
        return True, f"Forbidden reserved address/range: {parsed}"

    # 7. Unspecified (0.0.0.0 or ::)
    if parsed.is_unspecified:
        return True, f"Forbidden unspecified address/range: {parsed}"

    return False, "Routable public target"


def validate_and_normalize(
    target: str,
    custom_allowlist: list[str] | None = None,
) -> tuple[bool, str, str | None]:
    """
    Validate and normalize an IP address or CIDR network.

    Args:
        target: IP or CIDR string (e.g. '198.51.100.1' or '203.0.113.0/24').
        custom_allowlist: Optional list of allowlisted IPs / subnets to suppress.

    Returns:
        (is_valid, reason, normalized_target)
    """
    if not target or not isinstance(target, str):
        return False, "Empty or non-string indicator", None

    cleaned = target.strip()
    if not cleaned:
        return False, "Blank indicator", None

    parsed = parse_ip_or_network(cleaned)
    if parsed is None:
        return False, f"Invalid IPv4/IPv6 syntax: {cleaned}", None

    is_prot, reason = is_protected_network(parsed, custom_allowlist)
    if is_prot:
        return False, reason, None

    # If single-host network (e.g. 198.51.100.1/32), normalize to bare IP
    if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and parsed.num_addresses == 1:
        return True, "Valid routable host", str(parsed.network_address)

    return True, "Valid routable target", str(parsed)


def validate_indicator(target: str) -> tuple[bool, str, str | None]:
    """Compatibility alias for validate_and_normalize without custom allowlist."""
    return validate_and_normalize(target)


def sanitize_indicators(
    indicators: list[RawIndicator],
    custom_allowlist: list[str] | None = None,
) -> tuple[list[RawIndicator], list[tuple[RawIndicator, str]]]:
    """
    Filter out bogons, loopbacks, private IPs, and allowlisted targets from raw indicators.

    Returns:
        (valid_indicators, rejected_indicators_with_reasons)
    """
    valid: list[RawIndicator] = []
    rejected: list[tuple[RawIndicator, str]] = []

    for ind in indicators:
        is_val, reason, norm_ip = validate_and_normalize(ind.ip, custom_allowlist)
        if is_val and norm_ip is not None:
            ind.ip = norm_ip
            valid.append(ind)
        else:
            logger.debug("Filtered out indicator '%s' (%s): %s", ind.ip, ind.source, reason)
            rejected.append((ind, reason))

    return valid, rejected
