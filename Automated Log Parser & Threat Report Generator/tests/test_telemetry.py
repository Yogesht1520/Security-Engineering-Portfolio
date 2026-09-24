"""Tests for structured telemetry and JSON-lines metrics emission."""
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from analyzer.models import Finding, ParserStats
from analyzer.telemetry import TelemetryEmitter


def test_telemetry_emitter_to_stream():
    stream = io.StringIO()
    emitter = TelemetryEmitter(stream=stream)

    emitter.emit_scan_start("access.log", file_size_bytes=1024)
    emitter.emit_progress(lines_processed=100, malformed_lines=2, findings_count=5, elapsed_seconds=0.1)

    f = Finding(
        rule_id="SQLI-001",
        severity="CRITICAL",
        attack_type="SQL Injection",
        ip="1.2.3.4",
        timestamp=datetime(2026, 9, 24, tzinfo=timezone.utc),
        evidence="SELECT 1,2,3",
        location="URI",
        description="SQL attack",
    )
    emitter.emit_finding(f)

    stats = ParserStats(total_lines=100, parsed_lines=98, malformed_lines=2)
    stats.start_time = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
    stats.end_time = datetime(2026, 9, 24, 12, 0, 1, tzinfo=timezone.utc)
    emitter.emit_scan_complete(stats=stats, findings_count=5, incidents_count=1)

    output = stream.getvalue()
    lines = [json.loads(line) for line in output.strip().splitlines()]

    assert len(lines) == 4
    assert lines[0]["event_type"] == "scan_started"
    assert lines[1]["event_type"] == "scan_progress"
    assert lines[2]["event_type"] == "threat_detected"
    assert lines[3]["event_type"] == "scan_completed"


def test_telemetry_emitter_to_file(tmp_path: Path):
    out_file = tmp_path / "telemetry.jsonl"
    emitter = TelemetryEmitter(output_file=out_file)

    emitter.emit_scan_start("test.log", 500)
    emitter.close()

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "scan_started" in content
