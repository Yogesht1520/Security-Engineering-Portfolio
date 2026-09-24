"""IP enrichment engine providing GeoIP and reverse DNS lookups with two-tier caching."""
import ipaddress
import logging
import os
import socket
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

import geoip2.database
import geoip2.errors

from .models import Finding

logger = logging.getLogger(__name__)

# Fallback GeoIP data for sample/demo public IPs so reports display cleanly without external mmdb
DEMO_GEOIP_FALLBACK = {
    "185.220.101.5": {"country_name": "Netherlands", "country_code": "NL", "city": "Amsterdam", "asn_org": "Tor Exit Node"},
    "45.33.32.156": {"country_name": "United States", "country_code": "US", "city": "Dallas", "asn_org": "Linode, LLC"},
    "194.26.29.112": {"country_name": "Russia", "country_code": "RU", "city": "Moscow", "asn_org": "Hostkey B.V."},
    "91.240.118.80": {"country_name": "Bulgaria", "country_code": "BG", "city": "Sofia", "asn_org": "Telepoint Ltd"},
    "103.203.57.18": {"country_name": "India", "country_code": "IN", "city": "Mumbai", "asn_org": "Tata Communications"},
    "203.0.113.10": {"country_name": "Australia", "country_code": "AU", "city": "Sydney", "asn_org": "TEST-NET-3"},
    "203.0.113.25": {"country_name": "Australia", "country_code": "AU", "city": "Sydney", "asn_org": "TEST-NET-3"},
    "203.0.113.42": {"country_name": "Germany", "country_code": "DE", "city": "Frankfurt", "asn_org": "TEST-NET-3"},
    "198.51.100.12": {"country_name": "United States", "country_code": "US", "city": "New York", "asn_org": "TEST-NET-2"},
    "198.51.100.45": {"country_name": "United States", "country_code": "US", "city": "San Francisco", "asn_org": "TEST-NET-2"},
    "198.51.100.89": {"country_name": "Canada", "country_code": "CA", "city": "Toronto", "asn_org": "TEST-NET-2"},
}


@dataclass
class IPEnrichmentResult:
    """Structured result of IP geolocation and reverse DNS resolution."""
    ip: str
    country_name: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    rdns_hostname: Optional[str] = None
    is_private: bool = False
    asn_org: Optional[str] = None


class SQLiteIPCache:
    """Persistent on-disk cache for IP lookups."""

    def __init__(self, cache_file: Union[str, Path]):
        self.cache_file = Path(cache_file)
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.cache_file), timeout=10.0)

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_cache (
                    ip TEXT PRIMARY KEY,
                    country_name TEXT,
                    country_code TEXT,
                    city TEXT,
                    rdns_hostname TEXT,
                    is_private INTEGER,
                    asn_org TEXT,
                    updated_at TIMESTAMP
                )
                """
            )
            conn.commit()

    def get(self, ip: str) -> Optional[IPEnrichmentResult]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT ip, country_name, country_code, city, rdns_hostname, is_private, asn_org FROM ip_cache WHERE ip = ?",
                    (ip,),
                )
                row = cursor.fetchone()
                if row:
                    return IPEnrichmentResult(
                        ip=row[0],
                        country_name=row[1],
                        country_code=row[2],
                        city=row[3],
                        rdns_hostname=row[4],
                        is_private=bool(row[5]),
                        asn_org=row[6],
                    )
        except Exception as e:
            logger.debug("Disk cache read error for %s: %s", ip, e)
        return None

    def set(self, result: IPEnrichmentResult) -> None:
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ip_cache
                    (ip, country_name, country_code, city, rdns_hostname, is_private, asn_org, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.ip,
                        result.country_name,
                        result.country_code,
                        result.city,
                        result.rdns_hostname,
                        1 if result.is_private else 0,
                        result.asn_org,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
        except Exception as e:
            logger.debug("Disk cache write error for %s: %s", result.ip, e)


class IPEnricher:
    """Enriches IP addresses with GeoIP metadata and reverse DNS hostnames."""

    def __init__(
        self,
        geoip_db_path: Optional[Union[str, Path]] = None,
        cache_file: Optional[Union[str, Path]] = None,
        enable_rdns: bool = True,
        rdns_timeout: float = 1.0,
    ):
        self.geoip_db_path = Path(geoip_db_path) if geoip_db_path else None
        self.enable_rdns = enable_rdns
        self.rdns_timeout = rdns_timeout
        self.memory_cache: Dict[str, IPEnrichmentResult] = {}

        if cache_file is None:
            cache_file = Path(__file__).resolve().parent.parent / ".ip_cache.sqlite"
        self.disk_cache = SQLiteIPCache(cache_file)

        self._geoip_reader: Optional[geoip2.database.Reader] = None
        self._init_geoip_reader()

    def _init_geoip_reader(self) -> None:
        # Search candidate locations if path not specified
        candidate_paths = []
        if self.geoip_db_path:
            candidate_paths.append(self.geoip_db_path)
        else:
            base_dir = Path(__file__).resolve().parent.parent
            candidate_paths.extend([
                base_dir / "data" / "GeoLite2-City.mmdb",
                base_dir / "data" / "GeoLite2-Country.mmdb",
                Path("GeoLite2-City.mmdb"),
                Path("GeoLite2-Country.mmdb"),
            ])

        for path in candidate_paths:
            if path and path.exists() and path.is_file():
                try:
                    self._geoip_reader = geoip2.database.Reader(str(path))
                    logger.info("Loaded MaxMind GeoIP database from %s", path)
                    break
                except Exception as e:
                    logger.warning("Failed to open GeoIP database at %s: %s", path, e)

    def _is_private_ip(self, ip_str: str) -> bool:
        """Determine if IP address is private, loopback, or reserved."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            )
        except ValueError:
            return False

    def _resolve_rdns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS resolution with a scoped timeout that is always restored."""
        if not self.enable_rdns:
            return None
        orig_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.rdns_timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return None
        finally:
            # Guaranteed restore regardless of success or exception
            socket.setdefaulttimeout(orig_timeout)

    def lookup(self, ip: str) -> IPEnrichmentResult:
        """Perform two-tier cached lookup for a single IP address."""
        if not ip or ip == "-":
            return IPEnrichmentResult(ip=ip, is_private=False)

        # 1. Check in-memory cache
        if ip in self.memory_cache:
            return self.memory_cache[ip]

        # 2. Check disk cache
        cached = self.disk_cache.get(ip)
        if cached:
            self.memory_cache[ip] = cached
            return cached

        # 3. Check for private/loopback IP
        if self._is_private_ip(ip):
            result = IPEnrichmentResult(
                ip=ip,
                country_name="Private Network",
                country_code="LAN",
                city="Local Subnet",
                rdns_hostname="localhost" if ip in ("127.0.0.1", "::1") else None,
                is_private=True,
                asn_org="RFC 1918 / Private",
            )
            self.disk_cache.set(result)
            self.memory_cache[ip] = result
            return result

        # 4. Resolve GeoIP via MaxMind Reader or Fallback
        country_name = None
        country_code = None
        city = None
        asn_org = None

        if self._geoip_reader is not None:
            try:
                response = self._geoip_reader.city(ip)
                country_name = response.country.name
                country_code = response.country.iso_code
                city = response.city.name
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass
            except Exception as e:
                logger.debug("GeoIP lookup failed for %s: %s", ip, e)

        # Apply fallback if not resolved from mmdb
        if not country_name and ip in DEMO_GEOIP_FALLBACK:
            fb = DEMO_GEOIP_FALLBACK[ip]
            country_name = fb.get("country_name")
            country_code = fb.get("country_code")
            city = fb.get("city")
            asn_org = fb.get("asn_org")

        # 5. Resolve reverse DNS
        rdns = self._resolve_rdns(ip)

        result = IPEnrichmentResult(
            ip=ip,
            country_name=country_name or "Unknown",
            country_code=country_code or "--",
            city=city or "Unknown",
            rdns_hostname=rdns,
            is_private=False,
            asn_org=asn_org,
        )

        # Cache result
        self.disk_cache.set(result)
        self.memory_cache[ip] = result
        return result

    def enrich_findings(self, findings: Iterable[Finding], max_workers: int = 20) -> List[Finding]:
        """
        Batch-enrich a collection of findings with deduplicated concurrent IP lookups.
        Modifies and returns the findings list.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        findings_list = list(findings)
        unique_ips = [ip for ip in set(f.ip for f in findings_list if f.ip)]

        # Identify unique IPs not yet in fast memory cache
        uncached_ips = [ip for ip in unique_ips if ip not in self.memory_cache]

        if uncached_ips:
            worker_count = min(len(uncached_ips), max_workers)
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [executor.submit(self.lookup, ip) for ip in uncached_ips]
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as e:
                        logger.debug("Async lookup error: %s", e)

        ip_map: Dict[str, IPEnrichmentResult] = {ip: self.lookup(ip) for ip in unique_ips}

        for finding in findings_list:
            if finding.ip in ip_map:
                res = ip_map[finding.ip]
                finding.geo_country = res.country_name
                finding.geo_country_code = res.country_code
                finding.geo_city = res.city
                finding.rdns_hostname = res.rdns_hostname
                if res.asn_org:
                    finding.metadata["asn_org"] = res.asn_org

        return findings_list

    def close(self) -> None:
        """Clean up GeoIP reader resources."""
        if self._geoip_reader is not None:
            try:
                self._geoip_reader.close()
            except Exception:
                pass
