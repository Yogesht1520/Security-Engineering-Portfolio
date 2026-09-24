"""Tests for SIEM ingestion forwarders (Splunk HEC, Elasticsearch, Webhooks)."""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from analyzer.correlation import Incident
from analyzer.forwarders import ElasticsearchForwarder, SplunkHECForwarder, WebhookForwarder
from analyzer.models import Finding


def make_test_data():
    summary = {"total_lines": 100, "total_findings": 1}
    incident = Incident(
        incident_id="INC-001",
        ip="192.0.2.1",
        title="Test Incident",
        severity="HIGH",
        findings=[],
        attack_vectors=["SQL Injection"],
        mitre_tactics=["T1190"],
        start_time=datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 9, 24, 12, 5, tzinfo=timezone.utc),
        confidence_score=0.9,
    )
    finding = Finding(
        rule_id="SQLI-001",
        severity="CRITICAL",
        attack_type="SQL Injection",
        ip="192.0.2.1",
        timestamp=datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc),
        evidence="SELECT 1,2,3",
        location="URI",
        description="SQL payload",
    )
    return summary, [incident], [finding]


@patch("urllib.request.urlopen")
def test_splunk_hec_forwarder(mock_urlopen):
    mock_res = MagicMock()
    mock_res.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_res

    forwarder = SplunkHECForwarder(
        hec_url="http://splunk.local:8088/services/collector/event",
        token="test-hec-token",
    )
    summary, incidents, findings = make_test_data()

    success = forwarder.forward(summary, incidents, findings)
    assert success is True
    assert mock_urlopen.called


@patch("urllib.request.urlopen")
def test_elasticsearch_forwarder(mock_urlopen):
    mock_res = MagicMock()
    mock_res.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_res

    forwarder = ElasticsearchForwarder(
        es_url="http://elasticsearch.local:9200",
        index_prefix="test-threats",
    )
    summary, incidents, findings = make_test_data()

    success = forwarder.forward(summary, incidents, findings)
    assert success is True
    assert mock_urlopen.called


@patch("urllib.request.urlopen")
def test_webhook_forwarder(mock_urlopen):
    mock_res = MagicMock()
    mock_res.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_res

    forwarder = WebhookForwarder(webhook_url="https://hooks.slack.com/services/test")
    summary, incidents, findings = make_test_data()

    success = forwarder.forward(summary, incidents, findings)
    assert success is True
    assert mock_urlopen.called
