"""Tests for HTTP REST API service mode endpoints."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path
import pytest

from analyzer.service import create_service


@pytest.fixture(scope="module")
def api_server():
    server = create_service(host="127.0.0.1", port=18080, enable_rdns=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield "http://127.0.0.1:18080"
    server.shutdown()
    server.server_close()


def test_api_health(api_server):
    url = f"{api_server}/api/v1/health"
    with urllib.request.urlopen(url) as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert data["status"] == "healthy"
        assert data["detectors_loaded"] >= 5


def test_api_rules(api_server):
    url = f"{api_server}/api/v1/rules"
    with urllib.request.urlopen(url) as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert "rules" in data
        assert len(data["rules"]) >= 5


def test_api_scan_endpoint(api_server):
    url = f"{api_server}/api/v1/scan"
    sample_log = (
        '192.0.2.1 - - [24/Sep/2026:12:00:00 +0000] "GET /search?q=\' UNION SELECT 1,2,3-- HTTP/1.1" 200 123 "-" "sqlmap/1.7"\n'
        '192.0.2.2 - - [24/Sep/2026:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 456 "-" "Mozilla/5.0"\n'
    )
    req = urllib.request.Request(
        url,
        data=sample_log.encode("utf-8"),
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        report = json.loads(res.read().decode("utf-8"))
        assert "schema_version" in report
        assert report["summary"]["total_findings"] >= 1
        assert len(report["findings"]) >= 1


def test_api_enrich_endpoint(api_server):
    url = f"{api_server}/api/v1/enrich"
    req = urllib.request.Request(
        url,
        data=json.dumps({"ip": "10.0.0.1"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert data["ip"] == "10.0.0.1"
        assert data["is_private"] is True
