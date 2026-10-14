"""
dashboard/app.py — SOC blocklist management console (Flask)
============================================================
Provides real-time visibility into the Threat Intelligence IP Blacklist:
  - Top metrics (Total blocked, Added today, Expiring soon, Active feeds)
  - 30-day blocklist size trend chart (Plotly)
  - Searchable and sortable indicators table with color-coded severity badges
  - Pipeline execution history from audit logs
  - REST API endpoints for telemetry integration
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path when running dashboard/app.py directly
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from flask import Flask, jsonify, render_template, request

from audit.logger import AuditLogger
from config import get_config
from enforcement.local_firewall import LocalFirewallAdapter
from siem.forwarder import SiemForwarder
from storage.db import ThreatIntelDB

logger = logging.getLogger(__name__)


def _get_adapter(cfg: dict) -> LocalFirewallAdapter | None:
    enf_cfg = cfg.get("enforcement", {})
    local_cfg = enf_cfg.get("local_firewall", {})
    if local_cfg.get("enabled", True):
        return LocalFirewallAdapter(local_cfg)
    return None


def _parse_iso(dt_val: Any) -> datetime | None:
    """Parse ISO datetime string to aware UTC datetime."""
    if not dt_val:
        return None
    if isinstance(dt_val, datetime):
        return dt_val if dt_val.tzinfo else dt_val.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(dt_val))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def compute_dashboard_stats(db: ThreatIntelDB, cfg: dict) -> dict[str, Any]:
    """Calculate real-time dashboard KPIs from SQLite state and configuration."""
    active = db.get_active()
    now = datetime.now(timezone.utc)
    one_day_ago = now - timedelta(hours=24)
    forty_eight_hours_later = now + timedelta(hours=48)

    added_today = 0
    expiring_soon = 0

    for row in active:
        first_seen = _parse_iso(row.get("first_seen"))
        expires_at = _parse_iso(row.get("expires_at"))

        if first_seen and first_seen >= one_day_ago:
            added_today += 1
        if expires_at and expires_at <= forty_eight_hours_later:
            expiring_soon += 1

    sources_cfg = cfg.get("sources", {})
    active_sources = [
        name for name, s_cfg in sources_cfg.items()
        if isinstance(s_cfg, dict) and s_cfg.get("enabled", False)
    ]

    return {
        "total_blocked": len(active),
        "added_today": added_today,
        "expiring_soon": expiring_soon,
        "active_sources": active_sources,
        "total_sources_configured": len(sources_cfg),
    }


def generate_trend_chart_html(audit_path: str | Path, total_active: int = 0) -> str:
    """Generate a Plotly dark-themed trend chart embedded as an HTML fragment."""
    try:
        import plotly.graph_objects as go

        audit_logger = AuditLogger(audit_path)
        recent_runs = audit_logger.get_recent_runs(limit=30)
        # Reverse to chronological order (oldest to newest)
        runs_chrono = list(reversed(recent_runs))

        x_vals: list[str] = []
        y_vals: list[int] = []

        for run in runs_chrono:
            ts = run.get("timestamp")
            summary = run.get("summary", {})
            active_count = summary.get("total_active_in_db")
            if active_count is None:
                active_count = summary.get("blocked", 0)

            if ts:
                formatted_ts = ts[:16].replace("T", " ")
                x_vals.append(formatted_ts)
                y_vals.append(active_count)

        # Fallback if no history yet: show current active count
        if not x_vals:
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
            x_vals = [now_str]
            y_vals = [total_active]

        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=x_vals,
                y=y_vals,
                mode="lines+markers",
                name="Blocked IPs",
                line=dict(color="#00F2FE", width=3),
                marker=dict(size=6, color="#00F2FE", symbol="circle"),
                fill="tozeroy",
                fillcolor="rgba(0, 242, 254, 0.08)",
            )
        )

        fig.update_layout(
            margin=dict(l=35, r=20, t=20, b=35),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="JetBrains Mono, monospace", size=11, color="#94A3B8"),
            xaxis=dict(
                showgrid=True,
                gridcolor="rgba(255, 255, 255, 0.05)",
                zeroline=False,
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor="rgba(255, 255, 255, 0.05)",
                zeroline=False,
            ),
            hovermode="x unified",
            showlegend=False,
            height=260,
        )

        return fig.to_html(
            full_html=False,
            include_plotlyjs="cdn",
            config={"displayModeBar": False, "responsive": True},
        )
    except Exception as exc:
        logger.warning("Could not generate Plotly chart: %s", exc)
        return (
            '<div class="chart-empty">'
            '<span class="text-muted">Trend chart unavailable: %s</span>'
            '</div>' % exc
        )


def create_app(
    cfg: dict | None = None,
    db_path: str | None = None,
    audit_path: str | None = None,
) -> Flask:
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    if cfg is None:
        try:
            cfg = get_config()
        except Exception:
            cfg = {}

    app_db_path = db_path or cfg.get("storage", {}).get("db_path", "data/threat_intel.db")
    app_audit_path = audit_path or cfg.get("audit", {}).get("log_path", "data/run_history.jsonl")

    if not Path(app_db_path).is_absolute() and app_db_path != ":memory:":
        app_db_path = str(_PROJECT_ROOT / app_db_path)
    if not Path(app_audit_path).is_absolute():
        app_audit_path = str(_PROJECT_ROOT / app_audit_path)

    app.config["THREAT_INTEL_CFG"] = cfg
    app.config["DB_PATH"] = app_db_path
    app.config["AUDIT_PATH"] = app_audit_path

    @app.route("/")
    def index() -> str:
        with ThreatIntelDB(app.config["DB_PATH"]) as db:
            db.init_schema()
            stats = compute_dashboard_stats(db, app.config["THREAT_INTEL_CFG"])
            indicators = db.get_active()
            feed_health = db.get_feed_health()

        chart_html = generate_trend_chart_html(
            app.config["AUDIT_PATH"],
            total_active=stats["total_blocked"],
        )

        audit_logger = AuditLogger(app.config["AUDIT_PATH"])
        recent_runs = audit_logger.get_recent_runs(limit=5)

        return render_template(
            "index.html.j2",
            stats=stats,
            indicators=indicators,
            feed_health=feed_health,
            chart_html=chart_html,
            recent_runs=recent_runs,
            now_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

    @app.route("/api/stats")
    def api_stats():
        with ThreatIntelDB(app.config["DB_PATH"]) as db:
            db.init_schema()
            stats = compute_dashboard_stats(db, app.config["THREAT_INTEL_CFG"])
        return jsonify(stats)

    @app.route("/api/feed-health")
    def api_feed_health():
        with ThreatIntelDB(app.config["DB_PATH"]) as db:
            db.init_schema()
            health = db.get_feed_health()
        return jsonify(health)

    @app.route("/api/indicators")
    def api_indicators():
        search_query = request.args.get("search", "").strip().lower()
        category_query = request.args.get("category", "").strip().lower()

        with ThreatIntelDB(app.config["DB_PATH"]) as db:
            db.init_schema()
            active = db.get_active()

        filtered: list[dict[str, Any]] = []
        for row in active:
            if category_query and row.get("category", "").lower() != category_query:
                continue
            if search_query:
                ip_match = search_query in row.get("ip", "").lower()
                cat_match = search_query in row.get("category", "").lower()
                sources_match = any(search_query in str(s).lower() for s in row.get("sources", []))
                if not (ip_match or cat_match or sources_match):
                    continue
            filtered.append(row)

        return jsonify(filtered)

    @app.route("/api/runs")
    def api_runs():
        limit = request.args.get("limit", 10, type=int)
        audit_logger = AuditLogger(app.config["AUDIT_PATH"])
        runs = audit_logger.get_recent_runs(limit=limit)
        return jsonify(runs)

    @app.route("/api/chart")
    def api_chart():
        with ThreatIntelDB(app.config["DB_PATH"]) as db:
            db.init_schema()
            active_count = len(db.get_active())
        chart_html = generate_trend_chart_html(app.config["AUDIT_PATH"], total_active=active_count)
        return jsonify({"chart_html": chart_html})

    @app.route("/api/indicators/<path:ip>/whitelist", methods=["POST"])
    def api_whitelist_indicator(ip: str):
        data = request.get_json(silent=True) or {}
        reason = data.get("reason", "Analyst classified as false positive")
        analyst = data.get("analyst", "SOC Analyst")

        cfg = app.config["THREAT_INTEL_CFG"]
        with ThreatIntelDB(app.config["DB_PATH"]) as db:
            db.init_schema()
            record = db.get_by_ip(ip)
            if not record:
                return jsonify({"success": False, "error": f"Indicator '{ip}' not found"}), 404

            db.update_status(
                ip=ip,
                status="whitelisted",
                reason=f"WHITELISTED by {analyst}: {reason}",
                enforced=False,
            )

        adapter = _get_adapter(cfg)
        if adapter:
            try:
                adapter.remove([ip])
            except Exception as exc:
                logger.warning("Failed to remove %s from firewall adapter: %s", ip, exc)

        siem = SiemForwarder(cfg.get("siem", {}))
        siem.emit_analyst_action(ip=ip, action="whitelist", reason=reason, analyst=analyst)

        return jsonify({
            "success": True,
            "message": f"Indicator '{ip}' successfully whitelisted and unblocked.",
            "ip": ip,
            "status": "whitelisted",
        })

    @app.route("/api/indicators/<path:ip>/unblock", methods=["POST"])
    def api_unblock_indicator(ip: str):
        data = request.get_json(silent=True) or {}
        reason = data.get("reason", "Manual early expiration by analyst")
        analyst = data.get("analyst", "SOC Analyst")

        cfg = app.config["THREAT_INTEL_CFG"]
        with ThreatIntelDB(app.config["DB_PATH"]) as db:
            db.init_schema()
            record = db.get_by_ip(ip)
            if not record:
                return jsonify({"success": False, "error": f"Indicator '{ip}' not found"}), 404

            db.update_status(
                ip=ip,
                status="expired",
                reason=f"EARLY UNBLOCK by {analyst}: {reason}",
                enforced=False,
            )

        adapter = _get_adapter(cfg)
        if adapter:
            try:
                adapter.remove([ip])
            except Exception as exc:
                logger.warning("Failed to remove %s from firewall adapter: %s", ip, exc)

        siem = SiemForwarder(cfg.get("siem", {}))
        siem.emit_analyst_action(ip=ip, action="unblock", reason=reason, analyst=analyst)

        return jsonify({
            "success": True,
            "message": f"Indicator '{ip}' successfully removed from active enforcement.",
            "ip": ip,
            "status": "expired",
        })

    return app


def main() -> None:
    cfg = get_config()
    dashboard_cfg = cfg.get("dashboard", {})
    host = dashboard_cfg.get("host", "127.0.0.1")
    port = dashboard_cfg.get("port", 5000)
    app = create_app(cfg)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
