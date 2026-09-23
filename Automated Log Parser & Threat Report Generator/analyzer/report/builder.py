"""Aggregates findings and generates executive HTML, Markdown, and JSON threat reports."""
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import jinja2

from ..models import Finding, ParserStats
from .charts import (
    build_attack_breakdown_chart,
    build_severity_chart,
    build_timeline_chart,
    build_top_ips_chart,
)

SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def country_code_to_emoji(country_code: Optional[str]) -> str:
    """Convert a two-letter ISO country code to a Unicode flag emoji."""
    if not country_code:
        return "🌐"
    code = country_code.upper()
    if code in ("LAN", "--", "PRIVATE", "LOCAL"):
        return "🔒"
    if len(code) != 2:
        return "🌐"
    try:
        return "".join(chr(127397 + ord(c)) for c in code)
    except Exception:
        return "🌐"


class ReportBuilder:
    """Compiles findings and parser metrics into multi-format reports."""

    def __init__(
        self,
        findings: List[Finding],
        stats: ParserStats,
        log_source: str = "web_access.log",
        title: str = "SOC Web Threat Analysis",
    ):
        self.findings = findings
        self.stats = stats
        self.log_source = log_source
        self.title = title

        self.templates_dir = Path(__file__).resolve().parent / "templates"
        self._jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.templates_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )

    def _compute_summary(self) -> Dict[str, Any]:
        total_findings = len(self.findings)
        unique_ips = {f.ip for f in self.findings if f.ip}
        unique_countries = {f.geo_country for f in self.findings if f.geo_country and f.geo_country != "Unknown"}

        attack_type_counts = Counter(f.attack_type for f in self.findings)
        top_attack_type, top_attack_count = (
            attack_type_counts.most_common(1)[0] if attack_type_counts else ("None", 0)
        )

        sev_counts = Counter(f.severity.upper() for f in self.findings)
        highest_severity = "LOW"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts[s] > 0:
                highest_severity = s
                break

        crit_high_count = sev_counts["CRITICAL"] + sev_counts["HIGH"]
        parse_health_pct = (
            (self.stats.parsed_lines / self.stats.total_lines * 100)
            if self.stats.total_lines > 0
            else 100.0
        )

        return {
            "log_source": self.log_source,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_lines": self.stats.total_lines,
            "parsed_lines": self.stats.parsed_lines,
            "malformed_lines": self.stats.malformed_lines,
            "duration_seconds": self.stats.duration_seconds,
            "lines_per_second": self.stats.lines_per_second,
            "total_findings": total_findings,
            "unique_attacker_ips": len(unique_ips),
            "unique_countries": len(unique_countries),
            "total_attack_types": len(attack_type_counts),
            "top_attack_type": top_attack_type,
            "top_attack_count": top_attack_count,
            "highest_severity": highest_severity,
            "critical_high_count": crit_high_count,
            "parse_health_pct": parse_health_pct,
            "severity_counts": dict(sev_counts),
            "attack_type_counts": dict(attack_type_counts),
        }

    def _compute_top_offenders(self, limit: int = 10) -> List[Dict[str, Any]]:
        ip_findings: Dict[str, List[Finding]] = {}
        for f in self.findings:
            if f.ip:
                ip_findings.setdefault(f.ip, []).append(f)

        sorted_ips = sorted(ip_findings.items(), key=lambda item: len(item[1]), reverse=True)[:limit]

        top_offenders = []
        for ip, flist in sorted_ips:
            first = flist[0]
            top_vector = Counter(f.attack_type for f in flist).most_common(1)[0][0]
            highest_sev = max(flist, key=lambda f: SEVERITY_WEIGHTS.get(f.severity.upper(), 0)).severity.upper()

            top_offenders.append({
                "ip": ip,
                "country_name": first.geo_country or "Unknown",
                "country_code": first.geo_country_code or "--",
                "flag_emoji": country_code_to_emoji(first.geo_country_code),
                "city": first.geo_city or "Unknown",
                "rdns_hostname": first.rdns_hostname,
                "asn_org": first.metadata.get("asn_org"),
                "count": len(flist),
                "top_attack_type": top_vector,
                "highest_severity": highest_sev,
            })

        return top_offenders

    def render_html(self) -> str:
        """Render standalone executive HTML report."""
        summary = self._compute_summary()
        top_offenders = self._compute_top_offenders()

        # Load style.css
        css_path = self.templates_dir / "style.css"
        inline_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

        # Build Plotly charts
        timeline_html = build_timeline_chart(self.findings)
        attack_donut_html = build_attack_breakdown_chart(self.findings)
        severity_bar_html = build_severity_chart(self.findings)
        top_ips_bar_html = build_top_ips_chart(self.findings)

        template = self._jinja_env.get_template("report.html.j2")
        return template.render(
            title=self.title,
            summary=summary,
            findings=self.findings,
            top_offenders=top_offenders,
            inline_css=inline_css,
            timeline_chart=timeline_html,
            attack_breakdown_chart=attack_donut_html,
            severity_chart=severity_bar_html,
            top_ips_chart=top_ips_bar_html,
        )

    def render_markdown(self) -> str:
        """Render executive Markdown threat summary."""
        summary = self._compute_summary()
        top_offenders = self._compute_top_offenders()

        lines = [
            f"# {self.title}",
            f"> Source Log: `{self.log_source}` | Generated: {summary['generated_at']}",
            "",
            "## 🛡️ Executive Summary",
            f"- **Total Events Analyzed:** {summary['total_lines']:,} ({summary['lines_per_second']:,.0f} lines/sec)",
            f"- **Total Security Threats Identified:** {summary['total_findings']}",
            f"- **Unique Malicious IPs:** {summary['unique_attacker_ips']} across {summary['unique_countries']} countries",
            f"- **Peak Severity:** `{summary['highest_severity']}` ({summary['critical_high_count']} Critical/High)",
            f"- **Primary Threat Vector:** {summary['top_attack_type']} ({summary['top_attack_count']} detections)",
            "",
            "### Threat Category Breakdown",
            "| Attack Type | Detections | Proportion |",
            "|---|---|---|",
        ]

        total = max(summary["total_findings"], 1)
        for atype, count in summary["attack_type_counts"].items():
            pct = (count / total) * 100
            lines.append(f"| {atype} | {count} | {pct:.1f}% |")

        lines.extend([
            "",
            "## 🚨 Top Malicious Origins",
            "| Attacker IP | Origin | rDNS / ASN | Threats | Top Vector | Severity |",
            "|---|---|---|---|---|---|",
        ])

        for off in top_offenders:
            origin = f"{off['flag_emoji']} {off['country_name']}"
            rdns = off["rdns_hostname"] or off["asn_org"] or "--"
            lines.append(
                f"| `{off['ip']}` | {origin} | {rdns} | {off['count']} | {off['top_attack_type']} | `{off['highest_severity']}` |"
            )

        lines.extend([
            "",
            "## 🔍 Findings Summary",
            f"Total findings: {len(self.findings)}. Full details available in exported JSON/HTML reports.",
        ])

        return "\n".join(lines)

    def render_json(self) -> str:
        """Render structured JSON report for SIEM and CI/CD pipelines."""
        summary = self._compute_summary()
        top_offenders = self._compute_top_offenders()

        findings_data = []
        for f in self.findings:
            findings_data.append({
                "rule_id": f.rule_id,
                "severity": f.severity,
                "attack_type": f.attack_type,
                "ip": f.ip,
                "timestamp": f.timestamp.isoformat(),
                "location": f.location,
                "description": f.description,
                "evidence": f.evidence,
                "geo_country": f.geo_country,
                "geo_country_code": f.geo_country_code,
                "geo_city": f.geo_city,
                "rdns_hostname": f.rdns_hostname,
                "metadata": f.metadata,
            })

        report_dict = {
            "title": self.title,
            "summary": summary,
            "top_offenders": top_offenders,
            "findings": findings_data,
        }

        return json.dumps(report_dict, indent=2)
