"""
reporting/digest.py — Automated scheduled-run reporting & alert dispatcher
==========================================================================
Generates structured executive digests after automated pipeline executions:
  - Markdown run summaries for cron / systemd logs & file archives
  - Webhook alerts (Slack, Discord, Teams, or generic HTTP collectors)
  - Critical alerts when circuit breakers trip or threat feeds experience outages
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Literal
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


@dataclass
class FeedDigest:
    name: str
    healthy: bool
    duration_ms: float
    indicators_received: int
    rejected_count: int
    error: str | None = None


@dataclass
class RunDigest:
    """Consolidated metrics and status summary for a pipeline execution."""
    run_id: str
    timestamp: datetime
    duration_seconds: float
    operational_state: str
    collected_raw: int
    unique_ips: int
    blocked_count: int
    log_only_count: int
    enforced_added: int
    enforced_removed: int
    enforced_skipped: int
    expired_count: int
    total_active_in_db: int
    is_dry_run: bool = False
    circuit_breaker_tripped: bool = False
    circuit_breaker_reason: str = ""
    feeds: list[FeedDigest] = field(default_factory=list)
    drift_detected: bool = False
    drift_details: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def has_critical_alert(self) -> bool:
        """Indicates whether this run warrants immediate operational attention."""
        return (
            self.circuit_breaker_tripped
            or self.operational_state == "FAIL_SAFE"
            or any(not f.healthy for f in self.feeds)
            or bool(self.errors)
        )

    def to_markdown(self) -> str:
        """Format an executive Markdown report for archival or reporting."""
        status_emoji = "🔴" if self.has_critical_alert else "🟢"
        mode_badge = "[DRY-RUN]" if self.is_dry_run else "[ACTIVE ENFORCEMENT]"

        lines: list[str] = [
            f"# {status_emoji} Threat Intelligence Pipeline Run Report {mode_badge}",
            "",
            f"- **Run ID:** `{self.run_id}`",
            f"- **Execution Time:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Duration:** {self.duration_seconds:.2f}s",
            f"- **Operational State:** `{self.operational_state}`",
            f"- **Active Blocklist Size:** `{self.total_active_in_db}` IPs/CIDRs",
            "",
        ]

        # Circuit breaker alert section
        if self.circuit_breaker_tripped:
            lines.extend([
                "> [!CAUTION]",
                f"> **SAFETY CIRCUIT BREAKER TRIGGERED**",
                f"> {self.circuit_breaker_reason}",
                "> Automated mutations were halted to prevent catastrophic mass blocking or unblocking.",
                "",
            ])

        # Summary KPIs table
        lines.extend([
            "### Pipeline Execution Metrics",
            "",
            "| Metric | Count | Description |",
            "| :--- | :--- | :--- |",
            f"| Raw Indicators | {self.collected_raw} | Harvested across all enabled sources |",
            f"| Deduplicated Targets | {self.unique_ips} | Unique IP addresses & CIDR subnets |",
            f"| Policy Blocks | {self.blocked_count} | Scored at or above confidence threshold |",
            f"| Log-Only (Monitored) | {self.log_only_count} | Scored below threshold or allowlisted |",
            f"| Firewall Additions | +{self.enforced_added} | Net-new indicators pushed to firewall |",
            f"| Firewall Removals | -{self.enforced_removed} | Expired/orphan rules purged from firewall |",
            f"| Enforcer Skipped | {self.enforced_skipped} | Already present in firewall state |",
            f"| TTL Expirations | {self.expired_count} | Records whose TTL window elapsed |",
            "",
        ])

        # Threat feed health table
        if self.feeds:
            lines.extend([
                "### Threat Feed Availability & Latency",
                "",
                "| Feed Name | Health | Latency | Received | Rejected (Bogons) | Note |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for f in self.feeds:
                badge = "✅ Healthy" if f.healthy else "❌ Failed"
                err = f.error or "OK"
                lines.append(
                    f"| **{f.name}** | {badge} | {f.duration_ms:.1f}ms | {f.indicators_received} | {f.rejected_count} | {err} |"
                )
            lines.append("")

        # Drift & Reconciliation
        if self.drift_detected:
            orphans = len(self.drift_details.get("orphan_firewall_rules", []))
            missing = len(self.drift_details.get("missing_firewall_rules", []))
            lines.extend([
                "> [!WARNING]",
                f"> **Firewall Drift Detected**: {orphans} orphan rules, {missing} missing rules.",
                "",
            ])

        return "\n".join(lines)

    def to_slack_webhook_payload(self) -> dict[str, Any]:
        """Format a rich Slack/Discord-compatible Block Kit webhook payload."""
        alert_prefix = "🚨 ALERT: " if self.has_critical_alert else "ℹ️ Report: "
        headline = f"{alert_prefix}Threat Intel Engine Run ({self.operational_state})"

        text_summary = (
            f"*{headline}*\n"
            f"• *Status:* `{self.operational_state}` ({'DRY-RUN' if self.is_dry_run else 'ACTIVE'})\n"
            f"• *Active Blocklist:* {self.total_active_in_db} IPs\n"
            f"• *Changes:* +{self.enforced_added} added, -{self.enforced_removed} removed\n"
            f"• *Duration:* {self.duration_seconds:.2f}s"
        )
        if self.circuit_breaker_tripped:
            text_summary += f"\n⚠️ *Circuit Breaker Tripped:* {self.circuit_breaker_reason}"

        return {
            "text": headline,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": text_summary,
                    },
                }
            ],
        }


class ReportManager:
    """Manages report archiving and alert dispatching."""

    def __init__(self, reporting_cfg: dict[str, Any] | None = None) -> None:
        cfg = reporting_cfg or {}
        self.enabled: bool = bool(cfg.get("enabled", True))
        self.reports_dir: Path = Path(cfg.get("reports_dir", "data/reports"))
        self.webhook_url: str | None = cfg.get("webhook_url")
        self.notify_on_alert_only: bool = bool(cfg.get("notify_on_alert_only", False))

    def save_markdown_digest(self, digest: RunDigest) -> Path:
        """Write the run digest to latest and timestamped Markdown reports."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        content = digest.to_markdown()

        # 1. Update latest pointer
        latest_file = self.reports_dir / "latest_run.md"
        latest_file.write_text(content, encoding="utf-8")

        # 2. Archive timestamped copy
        run_file = self.reports_dir / f"run_{digest.run_id}.md"
        run_file.write_text(content, encoding="utf-8")

        return latest_file

    def dispatch_webhook(self, digest: RunDigest, timeout: float = 5.0) -> bool:
        """
        Send a webhook notification to Slack, Discord, or generic collector.
        Returns True if successful, False otherwise.
        """
        if not self.webhook_url:
            return False

        if self.notify_on_alert_only and not digest.has_critical_alert:
            logger.debug("Skipping webhook: notify_on_alert_only is True and no critical condition met")
            return False

        payload = digest.to_slack_webhook_payload()
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=req_data,
            headers={"Content-Type": "application/json", "User-Agent": "ThreatIntelEngine-Reporter/1.0"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                return 200 <= status < 300
        except Exception as exc:
            logger.warning("Failed to dispatch reporting webhook (non-fatal): %s", exc)
            return False
