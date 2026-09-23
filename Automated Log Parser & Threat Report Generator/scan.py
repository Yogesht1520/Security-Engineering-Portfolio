#!/usr/bin/env python3
"""CLI Entrypoint for Automated Log Parser & Threat Report Generator."""
import os
import sys
import webbrowser
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import click
from analyzer.detectors import DetectionEngine
from analyzer.enrichment import IPEnricher
from analyzer.models import ParserStats
from analyzer.parser import LogParser
from analyzer.report import ReportBuilder


@click.command(help="🛡️ Ingest web server access logs, detect cyber threats, and generate executive SOC reports.")
@click.argument("log_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-o",
    "--out",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("report.html"),
    help="Output report destination path (default: report.html).",
)
@click.option(
    "-f",
    "--format",
    "report_format",
    type=click.Choice(["html", "markdown", "md", "json", "all"], case_sensitive=False),
    default=None,
    help="Output format: html, markdown, json, or all (defaults to extension of --out).",
)
@click.option(
    "--rules-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Custom directory containing YAML detection rules.",
)
@click.option(
    "--geoip-db",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to MaxMind GeoLite2-City.mmdb or GeoLite2-Country.mmdb database.",
)
@click.option(
    "--no-rdns",
    is_flag=True,
    default=False,
    help="Disable reverse DNS hostname resolution.",
)
@click.option(
    "--log-format",
    type=click.Choice(["auto", "combined", "common"], case_sensitive=False),
    default="auto",
    help="Log format schema (default: auto).",
)
@click.option(
    "--title",
    type=str,
    default="SOC Web Threat Analysis Report",
    help="Custom title for the threat report.",
)
@click.option(
    "--open",
    "open_browser",
    is_flag=True,
    default=False,
    help="Automatically open the generated HTML report in your default web browser.",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress terminal output banner.",
)
def main(
    log_file: Path,
    output_file: Path,
    report_format: Optional[str],
    rules_dir: Optional[Path],
    geoip_db: Optional[Path],
    no_rdns: bool,
    log_format: str,
    title: str,
    open_browser: bool,
    quiet: bool,
):
    """Execute log analysis pipeline: Stream -> Parse -> Detect -> Enrich -> Report."""
    if not quiet:
        click.secho("\n🛡️  =======================================================", fg="cyan", bold=True)
        click.secho("    Automated Log Parser & Threat Report Generator", fg="bright_white", bold=True)
        click.secho("    SOC / SIEM Threat Analysis & Geolocation Pipeline", fg="cyan")
        click.secho("🛡️  =======================================================\n", fg="cyan", bold=True)
        click.echo(f"[*] Ingesting log file: {click.style(str(log_file), fg='yellow')}")

    # 1. Initialize Pipeline Components
    stats = ParserStats()
    parser = LogParser(log_format=log_format)
    engine = DetectionEngine(rules_dir=rules_dir)
    enricher = IPEnricher(
        geoip_db_path=geoip_db,
        enable_rdns=not no_rdns,
    )

    # 2. Stream Parse & Detect
    if not quiet:
        click.echo("[*] Streaming log lines & evaluating security detection rules...")

    entry_stream = parser.parse_stream(log_file, stats=stats)
    raw_findings = engine.process_stream(entry_stream)

    # 3. Enrich IP Findings
    if not quiet:
        click.echo(f"[*] Enriching {len(raw_findings)} identified threat events with GeoIP & rDNS...")

    enriched_findings = enricher.enrich_findings(raw_findings)
    enricher.close()

    # 4. Determine Output Format
    if report_format is None:
        suffix = output_file.suffix.lower()
        if suffix in (".md", ".markdown"):
            target_format = "markdown"
        elif suffix == ".json":
            target_format = "json"
        else:
            target_format = "html"
    else:
        target_format = report_format.lower()

    # 5. Build and Export Report
    builder = ReportBuilder(
        findings=enriched_findings,
        stats=stats,
        log_source=log_file.name,
        title=title,
    )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    generated_files = []

    if target_format in ("html", "all"):
        html_path = output_file if output_file.suffix.lower() == ".html" else output_file.with_suffix(".html")
        html_path.write_text(builder.render_html(), encoding="utf-8")
        generated_files.append(html_path)

    if target_format in ("markdown", "md", "all"):
        md_path = output_file if output_file.suffix.lower() in (".md", ".markdown") else output_file.with_suffix(".md")
        md_path.write_text(builder.render_markdown(), encoding="utf-8")
        generated_files.append(md_path)

    if target_format in ("json", "all"):
        json_path = output_file if output_file.suffix.lower() == ".json" else output_file.with_suffix(".json")
        json_path.write_text(builder.render_json(), encoding="utf-8")
        generated_files.append(json_path)

    # 6. Terminal Summary Banner
    if not quiet:
        click.secho("\n✅ Log Analysis Pipeline Completed Successfully!", fg="green", bold=True)
        click.echo("-" * 55)
        click.echo(f"  • Total Log Lines Processed : {click.style(f'{stats.total_lines:,}', bold=True)}")
        click.echo(f"  • Ingestion Throughput     : {click.style(f'{stats.lines_per_second:,.0f} lines/sec', fg='cyan')}")
        click.echo(f"  • Total Security Threats   : {click.style(str(len(enriched_findings)), fg='bright_red', bold=True)}")
        
        unique_ips = {f.ip for f in enriched_findings if f.ip}
        click.echo(f"  • Malicious Source IPs     : {click.style(str(len(unique_ips)), fg='yellow')}")
        click.echo("-" * 55)
        for gen_path in generated_files:
            click.echo(f"  [+] Report Saved: {click.style(str(gen_path.resolve()), fg='bright_green')}")
        click.echo()

    # 7. Auto-open in browser if requested
    if open_browser:
        for p in generated_files:
            if p.suffix.lower() == ".html":
                webbrowser.open(p.resolve().as_uri())
                break


if __name__ == "__main__":
    main()
