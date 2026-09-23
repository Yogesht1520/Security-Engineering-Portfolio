"""Unit tests for IPEnricher and disk caching."""
import sys
from datetime import datetime, timezone
from pathlib import Path
import pytest

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.enrichment import IPEnricher, SQLiteIPCache, IPEnrichmentResult
from analyzer.models import Finding


def test_private_ip_classification(tmp_path: Path):
    cache_file = tmp_path / "cache.sqlite"
    enricher = IPEnricher(cache_file=cache_file, enable_rdns=False)

    res_loopback = enricher.lookup("127.0.0.1")
    assert res_loopback.is_private is True
    assert res_loopback.country_name == "Private Network"
    assert res_loopback.country_code == "LAN"

    res_rfc1918 = enricher.lookup("192.168.1.100")
    assert res_rfc1918.is_private is True
    assert res_rfc1918.country_name == "Private Network"

    res_10net = enricher.lookup("10.50.1.1")
    assert res_10net.is_private is True


def test_disk_cache_persistence(tmp_path: Path):
    cache_file = tmp_path / "persistent_cache.sqlite"
    
    # Instance 1: write to cache
    enricher1 = IPEnricher(cache_file=cache_file, enable_rdns=False)
    res1 = enricher1.lookup("185.220.101.5")
    assert res1.country_name == "Netherlands"
    assert res1.country_code == "NL"

    # Instance 2: read from the exact same disk cache without performing new lookup
    enricher2 = IPEnricher(cache_file=cache_file, enable_rdns=False)
    # Check disk cache directly
    disk_res = enricher2.disk_cache.get("185.220.101.5")
    assert disk_res is not None
    assert disk_res.country_name == "Netherlands"
    assert disk_res.country_code == "NL"

    # Lookup via enricher2
    res2 = enricher2.lookup("185.220.101.5")
    assert res2.country_name == "Netherlands"
    assert res2.country_code == "NL"


def test_memory_cache_hit(tmp_path: Path):
    cache_file = tmp_path / "mem_cache.sqlite"
    enricher = IPEnricher(cache_file=cache_file, enable_rdns=False)

    ip = "45.33.32.156"
    res = enricher.lookup(ip)
    assert res.country_code == "US"
    assert ip in enricher.memory_cache
    assert enricher.memory_cache[ip].country_name == "United States"


def test_enrich_findings_batch(tmp_path: Path):
    cache_file = tmp_path / "findings_cache.sqlite"
    enricher = IPEnricher(cache_file=cache_file, enable_rdns=False)

    findings = [
        Finding(
            rule_id="SQLI-001",
            severity="CRITICAL",
            attack_type="SQL Injection",
            ip="185.220.101.5",
            timestamp=datetime.now(timezone.utc),
            evidence="UNION SELECT",
            description="SQLi detected",
        ),
        Finding(
            rule_id="TRAV-001",
            severity="HIGH",
            attack_type="Path Traversal",
            ip="45.33.32.156",
            timestamp=datetime.now(timezone.utc),
            evidence="../../etc/passwd",
            description="Traversal detected",
        ),
        Finding(
            rule_id="BRUTE-001",
            severity="HIGH",
            attack_type="Brute-Force Attack",
            ip="192.168.1.1",
            timestamp=datetime.now(timezone.utc),
            evidence="15 attempts",
            description="Brute force detected",
        ),
    ]

    enriched = enricher.enrich_findings(findings)

    assert enriched[0].geo_country == "Netherlands"
    assert enriched[0].geo_country_code == "NL"
    assert enriched[0].metadata.get("asn_org") == "Tor Exit Node"

    assert enriched[1].geo_country == "United States"
    assert enriched[1].geo_country_code == "US"

    assert enriched[2].geo_country == "Private Network"
    assert enriched[2].geo_country_code == "LAN"


def test_rdns_resolution_handling(tmp_path: Path):
    cache_file = tmp_path / "rdns_cache.sqlite"
    # Localhost should resolve cleanly or fail gracefully without throwing
    enricher = IPEnricher(cache_file=cache_file, enable_rdns=True, rdns_timeout=0.5)
    res = enricher.lookup("127.0.0.1")
    assert res.is_private is True
    assert res.rdns_hostname == "localhost"

    # Non-routable bogus IP should return None without error
    res_bogus = enricher.lookup("192.0.2.1")
    assert res_bogus.rdns_hostname is None


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
