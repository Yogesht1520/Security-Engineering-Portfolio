#!/usr/bin/env python3
"""
geoip.py — Autonomous GeoIP Enrichment Utility

Enforces an explicit IANA-derived Special-Purpose and Bogon Address Policy:
- Implements deterministic pre-validation based on authoritative IANA Special-Purpose
  Address Registries (RFC 6890 / RFC 5735 / RFC 5156 / RFC 6598 / RFC 5737).
- Policy Contract: Prevents leakage of internal, benchmarking, documentation, or
  reserved addresses to external third-party lookup APIs.
- Maintenance Governance: Maintained against the official IANA IPv4 & IPv6 registries:
  https://www.iana.org/assignments/iana-ipv4-special-registry/
  https://www.iana.org/assignments/iana-ipv6-special-registry/
- Encrypted external HTTPS lookup via ip-api.com strictly for routable public unicast.
- Enriches: Country, City / Region, ISP, ASN.
- In-memory caching minimizes redundant outbound queries and respects rate limits.
"""

import sys
import time
import json
import threading
import ipaddress
import urllib.request
import urllib.error
from collections import OrderedDict

# Authoritative IANA Special-Purpose Address Policy (RFC 6890 / RFC 5735 / RFC 5156)
# Governed baseline of reserved, protocol-assignment, and non-routable address prefixes.
# Audited against the IANA IPv4 and IPv6 Special-Purpose Registries.
IANA_BOGON_POLICY_VERSION = "2026.1"
IANA_BOGON_NETWORKS = [
    # IPv4 Special Purpose & Bogons
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598 Shared Address Space (Carrier-Grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # RFC 3927 Link-Local / Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # RFC 6890 IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # RFC 5737 Documentation (TEST-NET-1)
    ipaddress.ip_network("192.88.99.0/24"),     # RFC 7526 6to4 Relay Anycast (Deprecated)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # RFC 2544 Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # RFC 5737 Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # RFC 5737 Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # RFC 5771 Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # RFC 1112 Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast

    # IPv6 Special Purpose & Bogons
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),           # Discard-Only
    ipaddress.ip_network("2001::/23"),          # IETF Protocol Assignments (including Teredo)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("2002::/16"),          # 6to4
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

class GeoIPCache:
    """Thread-safe, bounded LRU cache with TTL expiration for GeoIP enrichment."""
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 86400):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, ip: str) -> dict | None:
        with self._lock:
            if ip not in self._cache:
                return None
            data, timestamp = self._cache[ip]
            if time.time() - timestamp > self.ttl_seconds:
                del self._cache[ip]
                return None
            self._cache.move_to_end(ip)
            return data

    def set(self, ip: str, data: dict):
        with self._lock:
            if ip in self._cache:
                del self._cache[ip]
            elif len(self._cache) >= self.max_size:
                self._cache.popitem(last=False) # Evict oldest LRU entry
            self._cache[ip] = (data, time.time())

    def clear(self):
        with self._lock:
            self._cache.clear()

    def __len__(self):
        with self._lock:
            return len(self._cache)

# Global bounded, thread-safe cache instance (1000 entries max, 24-hour TTL)
_GEOIP_CACHE = GeoIPCache(max_size=1000, ttl_seconds=86400)

def is_bogon_or_special(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Evaluates whether an IP address belongs to any IANA special-purpose or bogon block."""
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
        return True, "RFC1918 / Loopback / Reserved"
    for net in IANA_BOGON_NETWORKS:
        if ip_obj in net:
            return True, f"Bogon prefix ({net})"
    return False, ""

def lookup_ip(ip_address: str) -> dict:
    clean_ip = ip_address.strip()

    # 0. Check thread-safe, TTL-bounded cache
    cached = _GEOIP_CACHE.get(clean_ip)
    if cached is not None:
        return cached

    # 1. IP address syntactic and scope validation
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError as e:
        return {
            "ip": clean_ip,
            "status": "error",
            "message": f"Invalid IP address format: {e}"
        }

    # 2. Authoritative Bogon & Special-Purpose Check — Never query third-party APIs for bogons
    bogon, reason = is_bogon_or_special(ip_obj)
    if bogon:
        result = {
            "ip": clean_ip,
            "status": "success",
            "country": "Bogon / Non-Routable",
            "city": reason,
            "region": "Special-Purpose Block",
            "isp": "IANA Reserved Routing",
            "asn": "AS0 (Bogon)"
        }
        _GEOIP_CACHE.set(clean_ip, result)
        return result

    # 3. Encrypted HTTPS external enrichment for public addresses
    url = f"https://ip-api.com/json/{clean_ip}?fields=status,message,country,city,regionName,isp,as,query"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SIEM-Lab-Enrichment/2.0 (Security Engineering Lab)"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                result = {
                    "ip": clean_ip,
                    "status": "success",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown")
                }
                _GEOIP_CACHE.set(clean_ip, result)
                return result
            else:
                return {
                    "ip": clean_ip,
                    "status": "fail",
                    "message": data.get("message", "Lookup failed")
                }
    except Exception as e:
        return {
            "ip": clean_ip,
            "status": "error",
            "message": str(e)
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 geoip.py <ip_address>")
        sys.exit(1)
    
    target_ip = sys.argv[1].strip()
    result = lookup_ip(target_ip)
    print(json.dumps(result, indent=2))
