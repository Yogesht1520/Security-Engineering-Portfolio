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
from analyzer.checkpoint import CheckpointManager
from analyzer.detectors import DetectionEngine
from analyzer.enrichment import IPEnricher
from analyzer.forwarders import ElasticsearchForwarder, SplunkHECForwarder, WebhookForwarder
from analyzer.models import ParserStats
from analyzer.parser import LogParser
from analyzer.readers import stream_lines_with_offsets
from analyzer.report import ReportBuilder
from analyzer.service import create_service
from analyzer.telemetry import TelemetryEmitter


@click.command(help="🛡️ Ingest web server access logs, detect cyber threats, and generate executive SOC reports.")
@click.argument("log_file", type=click.Path(dir_okay=False, path_type=Path), required=False)
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
    "--checkpoint",
    is_flag=True,
    default=False,
    help="Enable incremental scanning (tracks and resumes from byte offset).",
)
@click.option(
    "--checkpoint-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path(".scan_checkpoint.json"),
    help="Path to checkpoint state file (default: .scan_checkpoint.json).",
)
@click.option(
    "--telemetry-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to emit structured JSON-lines telemetry events.",
)
@click.option(
    "--json-logs",
    is_flag=True,
    default=False,
    help="Emit structured JSON telemetry directly to stderr.",
)
@click.option(
    "--serve",
    is_flag=True,
    default=False,
    help="Start HTTP REST API service mode for on-demand log analysis.",
)
@click.option(
    "--port",
    type=int,
    default=8080,
    help="Port for HTTP REST API service mode (default: 8080).",
)
@click.option(
    "--host",
    type=str,
    default="0.0.0.0",
    help="Host address for HTTP REST API service mode (default: 0.0.0.0).",
)
@click.option(
    "--forward-hec",
    "hec_url",
    type=str,
    default=None,
    help="Splunk HTTP Event Collector (HEC) URL to forward findings.",
)
@click.option(
    "--hec-token",
    type=str,
    default=None,
    help="Splunk HEC authorization token.",
)
@click.option(
    "--forward-es",
    "es_url",
    type=str,
    default=None,
    help="Elasticsearch / OpenSearch base URL for bulk ingestion.",
)
@click.option(
    "--es-index",
    type=str,
    default="threat-reports",
    help="Elasticsearch index prefix (default: threat-reports).",
)
@click.option(
    "--forward-webhook",
    "webhook_url",
    type=str,
    default=None,
    help="Webhook URL (Slack, MS Teams, SOC Alert) for real-time notifications.",
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
    log_file: Optional[Path],
    output_file: Path,
    report_format: Optional[str],
    rules_dir: Optional[Path],
    geoip_db: Optional[Path],
    no_rdns: bool,
    log_format: str,
    title: str,
    checkpoint: bool,
    checkpoint_file: Path,
    telemetry_file: Optional[Path],
    json_logs: bool,
    serve: bool,
    port: int,
    host: str,
    hec_url: Optional[str],
    hec_token: Optional[str],
    es_url: Optional[str],
    es_index: str,
    webhook_url: Optional[str],
    open_browser: bool,
    quiet: bool,
):
    """Execute log analysis pipeline: Stream -> Parse -> Detect -> Enrich -> Report / Forward."""
    # Handle Service Mode
    if serve:
        click.secho("\n🚀 Starting Automated Log Threat Analyzer API Service...", fg="cyan", bold=True)
        click.echo(f"[*] Binding to: {click.style(f'http://{host}:{port}', fg='bright_green')}")
        click.echo(f"[*] Health Check: {click.style(f'http://localhost:{port}/api/v1/health', fg='yellow')}")
        click.echo(f"[*] Endpoints: POST /api/v1/scan, POST /api/v1/enrich, GET /api/v1/rules")
        server = create_service(
            rules_dir=rules_dir,
            geoip_path=geoip_db,
            enable_rdns=not no_rdns,
            host=host,
            port=port,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            click.secho("\n[*] Shutting down API service.", fg="yellow")
            server.server_close()
            sys.exit(0)

    if not log_file:
        click.secho("Error: Missing argument 'LOG_FILE' (or specify --serve for API mode).", fg="red", err=True)
        sys.exit(1)

    if not log_file.exists():
        click.secho(f"Error: Log file not found: {log_file}", fg="red", err=True)
        sys.exit(1)

    if not quiet and not json_logs:
        click.secho("\n🛡️  =======================================================", fg="cyan", bold=True)
        click.secho("    Automated Log Parser & Threat Report Generator", fg="bright_white", bold=True)
        click.secho("    SOC / SIEM Threat Analysis & Geolocation Pipeline", fg="cyan")
        click.secho("🛡️  =======================================================\n", fg="cyan", bold=True)
        click.echo(f"[*] Ingesting log file: {click.style(str(log_file), fg='yellow')}")

    # Initialize Telemetry Emitter
    telemetry = TelemetryEmitter(
        output_file=telemetry_file,
        stream=sys.stderr if json_logs else None,
        enabled=(telemetry_file is not None or json_logs),
    )
    file_size = log_file.stat().st_size if log_file.exists() else 0
    telemetry.emit_scan_start(log_source=str(log_file), file_size_bytes=file_size)

    # Checkpoint Handling
    start_offset = 0
    cp_mgr = CheckpointManager(checkpoint_file) if (checkpoint or checkpoint_file) else None
    if checkpoint and cp_mgr:
        existing_cp = cp_mgr.load(log_file)
        if existing_cp:
            start_offset = existing_cp.byte_offset
            if not quiet and not json_logs:
                click.echo(f"[*] Resuming scan from byte offset {start_offset:,} (lines previously scanned: {existing_cp.lines_processed:,})")

    # 1. Initialize Pipeline Components
    stats = ParserStats()
    parser = LogParser(log_format=log_format)
    engine = DetectionEngine(rules_dir=rules_dir)
    enricher = IPEnricher(
        geoip_db_path=geoip_db,
        enable_rdns=not no_rdns,
    )

    # 2. Stream Parse & Detect with Offset Tracking
    if not quiet and not json_logs:
        click.echo("[*] Streaming log lines & evaluating security detection rules...")

    raw_findings = []
    latest_offset = start_offset

    if not log_file.suffix.lower() == ".gz" and (checkpoint or start_offset > 0):
        # Plaintext with exact offset tracking
        for line_num, line_str, current_offset in stream_lines_with_offsets(log_file, start_offset=start_offset):
            latest_offset = current_offset
            if not line_str or line_str.isspace():
                continue
            stats.total_lines += 1
            entry = parser.parse_line(line_str, line_number=line_num)
            if entry:
                stats.parsed_lines += 1
                findings = engine.process_entry(entry)
                if findings:
                    raw_findings.extend(findings)
                    for f in findings:
                        telemetry.emit_finding(f)
            else:
                stats.malformed_lines += 1
    else:
        entry_stream = parser.parse_stream(log_file, stats=stats, start_offset=start_offset)
        for entry in entry_stream:
            findings = engine.process_entry(entry)
            if findings:
                raw_findings.extend(findings)
                for f in findings:
                    telemetry.emit_finding(f)

    # Save Checkpoint if enabled
    if checkpoint and cp_mgr:
        cp_mgr.save(
            target_log_path=log_file,
            byte_offset=latest_offset,
            lines_processed=stats.total_lines,
        )
        if not quiet and not json_logs:
            click.echo(f"[*] Updated scan checkpoint: {latest_offset:,} bytes.")

    # 3. Enrich IP Findings
    if not quiet and not json_logs:
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

    summary_dict = builder._compute_summary()
    telemetry.emit_scan_complete(
        stats=stats,
        findings_count=len(enriched_findings),
        incidents_count=len(builder.incidents),
    )
    telemetry.close()

    # 6. SIEM & Webhook Forwarders
    if hec_url and hec_token:
        forwarder = SplunkHECForwarder(hec_url=hec_url, token=hec_token)
        success = forwarder.forward(summary=summary_dict, incidents=builder.incidents, findings=enriched_findings)
        if not quiet and not json_logs:
            status_tag = click.style("SUCCESS", fg="green") if success else click.style("FAILED", fg="red")
            click.echo(f"  [>] Splunk HEC Forwarding: [{status_tag}] -> {hec_url}")

    if es_url:
        forwarder = ElasticsearchForwarder(es_url=es_url, index_prefix=es_index)
        success = forwarder.forward(summary=summary_dict, incidents=builder.incidents, findings=enriched_findings)
        if not quiet and not json_logs:
            status_tag = click.style("SUCCESS", fg="green") if success else click.style("FAILED", fg="red")
            click.echo(f"  [>] Elasticsearch Forwarding: [{status_tag}] -> {es_url}")

    if webhook_url:
        forwarder = WebhookForwarder(webhook_url=webhook_url)
        success = forwarder.forward(summary=summary_dict, incidents=builder.incidents, findings=enriched_findings)
        if not quiet and not json_logs:
            status_tag = click.style("SUCCESS", fg="green") if success else click.style("FAILED", fg="red")
            click.echo(f"  [>] Webhook Alerting: [{status_tag}] -> {webhook_url}")

    # 7. Terminal Summary Banner
    if not quiet and not json_logs:
        click.secho("\n✅ Log Analysis Pipeline Completed Successfully!", fg="green", bold=True)
        click.echo("-" * 55)
        click.echo(f"  • Total Log Lines Processed : {click.style(f'{stats.total_lines:,}', bold=True)}")
        click.echo(f"  • Ingestion Throughput     : {click.style(f'{stats.lines_per_second:,.0f} lines/sec', fg='cyan')}")
        click.echo(f"  • Correlated Incidents     : {click.style(str(len(builder.incidents)), fg='bright_yellow', bold=True)}")
        click.echo(f"  • Total Security Threats   : {click.style(str(len(enriched_findings)), fg='bright_red', bold=True)}")
        
        unique_ips = {f.ip for f in enriched_findings if f.ip}
        click.echo(f"  • Malicious Source IPs     : {click.style(str(len(unique_ips)), fg='yellow')}")
        click.echo("-" * 55)
        for gen_path in generated_files:
            click.echo(f"  [+] Report Saved: {click.style(str(gen_path.resolve()), fg='bright_green')}")
        click.echo()

    # 8. Auto-open in browser if requested
    if open_browser:
        for p in generated_files:
            if p.suffix.lower() == ".html":
                webbrowser.open(p.resolve().as_uri())
                break


if __name__ == "__main__":
    main()
