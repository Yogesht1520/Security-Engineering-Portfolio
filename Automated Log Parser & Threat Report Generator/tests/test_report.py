"""Unit tests for ReportBuilder, charts, and report exports."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import pytest

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.models import Finding, ParserStats
from analyzer.report.builder import ReportBuilder, country_code_to_emoji
from analyzer.report.charts import (
    build_attack_breakdown_chart,
    build_severity_chart,
    build_timeline_chart,
    build_top_ips_chart,
)


@pytest.fixture
def sample_findings():
    return [
        Finding(
            rule_id="SQLI-001",
            severity="CRITICAL",
            attack_type="SQL Injection",
            ip="185.220.101.5",
            timestamp=datetime(2026, 9, 24, 10, 5, 0, tzinfo=timezone.utc),
            evidence="UNION SELECT null,password FROM users--",
            description="Union SQL injection detected",
            geo_country="Netherlands",
            geo_country_code="NL",
            geo_city="Amsterdam",
            rdns_hostname="tor-exit.net",
        ),
        Finding(
            rule_id="TRAV-001",
            severity="HIGH",
            attack_type="Path Traversal",
            ip="45.33.32.156",
            timestamp=datetime(2026, 9, 24, 10, 6, 0, tzinfo=timezone.utc),
            evidence="../../etc/passwd",
            description="Directory climbing detected",
            geo_country="United States",
            geo_country_code="US",
            geo_city="Dallas",
            rdns_hostname="li45-33.members.linode.com",
        ),
    ]


@pytest.fixture
def sample_stats():
    return ParserStats(
        total_lines=500,
        parsed_lines=498,
        malformed_lines=2,
        start_time=datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 9, 24, 10, 0, 1, tzinfo=timezone.utc),
    )


def test_country_code_to_emoji():
    assert country_code_to_emoji("US") == "🇺🇸"
    assert country_code_to_emoji("NL") == "🇳🇱"
    assert country_code_to_emoji("LAN") == "🔒"
    assert country_code_to_emoji(None) == "🌐"


def test_charts_generation(sample_findings):
    timeline = build_timeline_chart(sample_findings)
    assert "Threat Events Over Time" in timeline

    donut = build_attack_breakdown_chart(sample_findings)
    assert "Attack Vector Distribution" in donut

    sev_chart = build_severity_chart(sample_findings)
    assert "Findings by Severity" in sev_chart

    top_ips = build_top_ips_chart(sample_findings)
    assert "Malicious Sources" in top_ips


def test_report_builder_html_rendering(sample_findings, sample_stats):
    builder = ReportBuilder(
        findings=sample_findings,
        stats=sample_stats,
        log_source="attack_demo.log",
        title="Test SOC Threat Report",
    )
    html_output = builder.render_html()

    assert "<!DOCTYPE html>" in html_output
    assert "Test SOC Threat Report" in html_output
    assert "185.220.101.5" in html_output
    assert "45.33.32.156" in html_output
    assert "SQL Injection" in html_output
    assert "Path Traversal" in html_output
    assert "Netherlands" in html_output
    assert "CRITICAL" in html_output


def test_report_builder_markdown_rendering(sample_findings, sample_stats):
    builder = ReportBuilder(
        findings=sample_findings,
        stats=sample_stats,
        log_source="attack_demo.log",
    )
    md_output = builder.render_markdown()

    assert "# SOC Web Threat Analysis" in md_output
    assert "## 🛡️ Executive Summary" in md_output
    assert "185.220.101.5" in md_output
    assert "| SQL Injection |" in md_output


def test_report_builder_json_rendering(sample_findings, sample_stats):
    builder = ReportBuilder(
        findings=sample_findings,
        stats=sample_stats,
        log_source="attack_demo.log",
    )
    json_str = builder.render_json()
    data = json.loads(json_str)

    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total_findings"] == 2
    assert len(data["findings"]) == 2
    assert data["findings"][0]["rule_id"] == "SQLI-001"
    assert data["findings"][0]["geo_country_code"] == "NL"


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
