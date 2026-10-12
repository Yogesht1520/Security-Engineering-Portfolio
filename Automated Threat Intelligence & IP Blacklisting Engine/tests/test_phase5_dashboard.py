"""
tests/test_phase5_dashboard.py — Tests for Phase 5 SOC Dashboard & Scheduler
=============================================================================
Covers:
  - Flask application factory and route responses
  - Real-time KPI metrics calculation
  - REST API endpoints (/api/stats, /api/indicators, /api/runs, /api/chart)
  - Search and category query filtering
  - Plotly trend chart HTML generation
  - Systemd and crontab configuration unit validation
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from audit.logger import AuditLogger
from dashboard.app import compute_dashboard_stats, create_app, generate_trend_chart_html
from models import ScoredIP
from storage.db import ThreatIntelDB


@pytest.fixture
def test_setup(tmp_path):
    """Sets up an isolated test database and audit file."""
    db_file = tmp_path / "test_dashboard.db"
    audit_file = tmp_path / "test_audit.jsonl"

    db = ThreatIntelDB(str(db_file))
    db.init_schema()

    now = datetime.now(timezone.utc)
    # 1. Critical score indicator (>= 80), added today
    db.upsert(ScoredIP("198.51.100.1", 95.0, ["abuseipdb", "otx"], "brute_force", now - timedelta(hours=2), now + timedelta(days=29)))
    db.set_enforced("198.51.100.1", True)

    # 2. Medium score indicator (50-79), added 3 days ago, expiring soon (< 48h)
    db.upsert(ScoredIP("198.51.100.2", 65.0, ["spamhaus"], "spam", now - timedelta(days=3), now + timedelta(hours=12)))
    db.set_enforced("198.51.100.2", True)

    # 3. Low score indicator (< 50)
    db.upsert(ScoredIP("198.51.100.3", 45.0, ["abuseipdb"], "port_scan", now - timedelta(days=10), now + timedelta(days=20)))
    db.close()

    # Create dummy audit runs
    audit_logger = AuditLogger(audit_file)
    audit_logger.log_run({
        "run_id": "run-001",
        "timestamp": (now - timedelta(hours=6)).isoformat(),
        "duration_seconds": 1.2,
        "summary": {"blocked": 2, "expired_count": 0, "total_active_in_db": 2},
    })
    audit_logger.log_run({
        "run_id": "run-002",
        "timestamp": now.isoformat(),
        "duration_seconds": 1.5,
        "summary": {"blocked": 3, "expired_count": 0, "total_active_in_db": 3},
    })

    cfg = {
        "storage": {"db_path": str(db_file)},
        "audit": {"log_path": str(audit_file)},
        "sources": {
            "abuseipdb": {"enabled": True},
            "otx": {"enabled": True},
            "spamhaus": {"enabled": False},
        },
    }

    return {
        "db_path": str(db_file),
        "audit_path": str(audit_file),
        "cfg": cfg,
    }


# ─────────────────────────────────────────────────────────────────
# 1. Flask App Factory & Route Tests
# ─────────────────────────────────────────────────────────────────

class TestDashboardRoutes:
    def test_create_app_custom_paths(self, test_setup):
        app = create_app(
            cfg=test_setup["cfg"],
            db_path=test_setup["db_path"],
            audit_path=test_setup["audit_path"],
        )
        assert app.config["DB_PATH"] == test_setup["db_path"]
        assert app.config["AUDIT_PATH"] == test_setup["audit_path"]

    def test_index_route_status_200(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Threat Intel Engine" in html
        assert "SOC Console" in html

    def test_index_contains_metric_cards(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "Total Blocked IPs" in html
        assert "Added Today" in html
        assert "Expiring Soon" in html
        assert "Active Intel Feeds" in html

    def test_index_renders_with_populated_database(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "198.51.100.1" in html
        assert "198.51.100.2" in html
        assert "198.51.100.3" in html

    def test_score_badge_css_classes(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        # Score 95.0 -> badge-critical
        assert "badge-critical" in html
        # Score 65.0 -> badge-medium
        assert "badge-medium" in html
        # Score 45.0 -> badge-low
        assert "badge-low" in html

    def test_index_renders_with_empty_database(self, tmp_path):
        empty_db = tmp_path / "empty.db"
        empty_audit = tmp_path / "empty.jsonl"
        cfg = {
            "storage": {"db_path": str(empty_db)},
            "audit": {"log_path": str(empty_audit)},
            "sources": {},
        }
        app = create_app(cfg)
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "No active indicators found" in html


# ─────────────────────────────────────────────────────────────────
# 2. REST API Endpoints Tests
# ─────────────────────────────────────────────────────────────────

class TestApiEndpoints:
    def test_api_stats_returns_accurate_metrics(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_blocked"] == 3
        assert data["added_today"] == 1
        assert data["expiring_soon"] == 1
        assert data["active_sources"] == ["abuseipdb", "otx"]

    def test_api_indicators_json_structure(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/api/indicators")
        assert resp.status_code == 200
        items = resp.get_json()
        assert len(items) == 3
        ips = [i["ip"] for i in items]
        assert "198.51.100.1" in ips

    def test_api_indicators_search_filter(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/api/indicators?search=198.51.100.1")
        items = resp.get_json()
        assert len(items) == 1
        assert items[0]["ip"] == "198.51.100.1"

    def test_api_indicators_category_filter(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/api/indicators?category=spam")
        items = resp.get_json()
        assert len(items) == 1
        assert items[0]["ip"] == "198.51.100.2"

    def test_api_runs_returns_recent_history(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/api/runs?limit=1")
        assert resp.status_code == 200
        runs = resp.get_json()
        assert len(runs) == 1
        assert runs[0]["run_id"] == "run-002"

    def test_api_chart_returns_html(self, test_setup):
        app = create_app(test_setup["cfg"])
        client = app.test_client()
        resp = client.get("/api/chart")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "chart_html" in data
        assert "plotly" in data["chart_html"].lower()


# ─────────────────────────────────────────────────────────────────
# 3. Plotly Chart Tests
# ─────────────────────────────────────────────────────────────────

class TestPlotlyChart:
    def test_generate_trend_chart_html_output(self, test_setup):
        chart_html = generate_trend_chart_html(test_setup["audit_path"], total_active=3)
        assert isinstance(chart_html, str)
        assert len(chart_html) > 50
        assert "plotly" in chart_html.lower()

    def test_generate_trend_chart_empty_history_graceful(self, tmp_path):
        empty_log = tmp_path / "nonexistent.jsonl"
        chart_html = generate_trend_chart_html(empty_log, total_active=0)
        assert isinstance(chart_html, str)
        assert "plotly" in chart_html.lower()


# ─────────────────────────────────────────────────────────────────
# 4. Scheduler Unit Validation Tests
# ─────────────────────────────────────────────────────────────────

class TestSchedulerUnits:
    def test_systemd_service_file_validity(self):
        service_path = Path(__file__).parent.parent / "scheduler" / "threat-intel.service"
        assert service_path.exists()
        content = service_path.read_text(encoding="utf-8")
        assert "[Unit]" in content
        assert "[Service]" in content
        assert "Type=oneshot" in content
        assert "ExecStart=" in content
        assert "main.py" in content

    def test_systemd_timer_file_validity(self):
        timer_path = Path(__file__).parent.parent / "scheduler" / "threat-intel.timer"
        assert timer_path.exists()
        content = timer_path.read_text(encoding="utf-8")
        assert "[Unit]" in content
        assert "[Timer]" in content
        assert "OnUnitActiveSec=6h" in content
        assert "Persistent=true" in content
        assert "[Install]" in content
        assert "WantedBy=timers.target" in content

    def test_crontab_example_format(self):
        cron_path = Path(__file__).parent.parent / "scheduler" / "crontab.example"
        assert cron_path.exists()
        content = cron_path.read_text(encoding="utf-8")
        assert "0 */6 * * *" in content
        assert "main.py" in content
