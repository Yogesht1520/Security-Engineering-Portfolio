"""Unit tests for the Incident correlation engine."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.correlation import CorrelationEngine, Incident
from analyzer.models import Finding


def make_finding(
    ip: str,
    attack_type: str,
    rule_id: str,
    severity: str,
    dt: datetime,
    country: str = "United States",
    country_code: str = "US",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        attack_type=attack_type,
        ip=ip,
        timestamp=dt,
        evidence="payload match",
        description=f"{attack_type} detected",
        geo_country=country,
        geo_country_code=country_code,
        metadata={"mitre_attack_id": "T1190"},
    )


def test_correlation_single_ip_multi_vector_elevation():
    engine = CorrelationEngine(window_seconds=1800)
    base_time = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    attacker_ip = "185.220.101.5"

    findings = [
        make_finding(attacker_ip, "Scanner Reconnaissance", "SCAN-001", "HIGH", base_time),
        make_finding(attacker_ip, "Path Traversal", "TRAV-001", "HIGH", base_time + timedelta(minutes=5)),
        make_finding(attacker_ip, "SQL Injection", "SQLI-001", "CRITICAL", base_time + timedelta(minutes=10)),
    ]

    incidents = engine.correlate(findings)
    assert len(incidents) == 1
    inc = incidents[0]

    assert inc.ip == attacker_ip
    assert inc.severity == "CRITICAL"
    assert "Multi-Stage Cyber Attack Campaign" in inc.title
    assert len(inc.attack_vectors) == 3
    assert inc.finding_count == 3
    assert inc.confidence_score >= 0.90
    assert inc.geo_country == "United States"


def test_correlation_temporal_clustering():
    """Verify that events outside the correlation window split into separate incidents."""
    engine = CorrelationEngine(window_seconds=1800)  # 30 mins
    base_time = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    attacker_ip = "45.33.32.156"

    findings = [
        # Morning burst
        make_finding(attacker_ip, "Path Traversal", "TRAV-001", "HIGH", base_time),
        make_finding(attacker_ip, "Path Traversal", "TRAV-002", "HIGH", base_time + timedelta(minutes=2)),
        # Evening burst (4 hours later)
        make_finding(attacker_ip, "SQL Injection", "SQLI-001", "CRITICAL", base_time + timedelta(hours=4)),
    ]

    incidents = engine.correlate(findings)
    assert len(incidents) == 2
    assert incidents[0].severity == "CRITICAL"  # Highest severity incident first
    assert incidents[1].severity == "HIGH"


def test_correlation_empty_findings():
    engine = CorrelationEngine()
    assert engine.correlate([]) == []


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
