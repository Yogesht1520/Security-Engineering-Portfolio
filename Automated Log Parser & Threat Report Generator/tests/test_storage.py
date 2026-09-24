"""Unit tests for persistent SQLiteFindingStore."""
import sys
from datetime import datetime, timezone
from pathlib import Path
import pytest

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.models import Finding
from analyzer.storage import SQLiteFindingStore


def test_sqlite_finding_store(tmp_path: Path):
    db_file = tmp_path / "test_findings.db"
    store = SQLiteFindingStore(db_path=db_file)

    f1 = Finding(
        rule_id="SQLI-001",
        severity="CRITICAL",
        attack_type="SQL Injection",
        ip="185.220.101.5",
        timestamp=datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc),
        evidence="UNION SELECT",
        description="SQLi test",
        location="URI Path",
        geo_country="Netherlands",
        geo_country_code="NL",
        geo_city="Amsterdam",
        rdns_hostname="tor-exit.net",
        metadata={"mitre_attack_id": "T1190"},
    )

    f2 = Finding(
        rule_id="TRAV-001",
        severity="HIGH",
        attack_type="Path Traversal",
        ip="45.33.32.156",
        timestamp=datetime(2026, 9, 24, 12, 1, 0, tzinfo=timezone.utc),
        evidence="../../etc/passwd",
        description="Traversal test",
        location="URI Path",
        geo_country="United States",
        geo_country_code="US",
        geo_city="Dallas",
    )

    store.add_finding(f1)
    assert store.count() == 1

    store.add_findings([f2])
    assert store.count() == 2

    # Verify retrieval
    all_findings = store.get_all_findings()
    assert len(all_findings) == 2
    assert all_findings[0].rule_id == "SQLI-001"
    assert all_findings[0].geo_country == "Netherlands"
    assert all_findings[1].rule_id == "TRAV-001"
    assert all_findings[1].geo_city == "Dallas"


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
