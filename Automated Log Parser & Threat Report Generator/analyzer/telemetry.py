"""Structured telemetry and observability emitter for analyzer metrics."""
import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Union

from .models import Finding, ParserStats


@dataclass
class TelemetryEvent:
    """Standardized structured telemetry event."""
    timestamp: str
    event_type: str
    metrics: Dict[str, Any]
    details: Optional[Dict[str, Any]] = None

    def to_json(self) -> str:
        data = {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "metrics": self.metrics,
        }
        if self.details:
            data["details"] = self.details
        return json.dumps(data)


class TelemetryEmitter:
    """Emits structured JSON-lines events for SIEM/observability pipelines."""

    def __init__(
        self,
        output_file: Optional[Union[str, Path]] = None,
        stream: Optional[TextIO] = None,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.output_file = Path(output_file) if output_file else None
        self.stream = stream
        self.events: List[TelemetryEvent] = []
        self._file_handle: Optional[TextIO] = None

        if self.enabled and self.output_file:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(self.output_file, "a", encoding="utf-8")

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def emit(self, event_type: str, metrics: Dict[str, Any], details: Optional[Dict[str, Any]] = None) -> TelemetryEvent:
        """Create and emit a structured event."""
        if not self.enabled:
            return TelemetryEvent(timestamp=self._now(), event_type=event_type, metrics=metrics, details=details)

        event = TelemetryEvent(
            timestamp=self._now(),
            event_type=event_type,
            metrics=metrics,
            details=details,
        )
        self.events.append(event)
        json_line = event.to_json() + "\n"

        if self.stream:
            try:
                self.stream.write(json_line)
                self.stream.flush()
            except Exception:
                pass

        if self._file_handle:
            try:
                self._file_handle.write(json_line)
                self._file_handle.flush()
            except Exception:
                pass

        return event

    def emit_scan_start(self, log_source: str, file_size_bytes: int = 0) -> TelemetryEvent:
        return self.emit(
            event_type="scan_started",
            metrics={"file_size_bytes": file_size_bytes},
            details={"log_source": log_source},
        )

    def emit_progress(
        self,
        lines_processed: int,
        malformed_lines: int,
        findings_count: int,
        elapsed_seconds: float,
    ) -> TelemetryEvent:
        lps = (lines_processed / elapsed_seconds) if elapsed_seconds > 0 else 0.0
        return self.emit(
            event_type="scan_progress",
            metrics={
                "lines_processed": lines_processed,
                "malformed_lines": malformed_lines,
                "findings_count": findings_count,
                "elapsed_seconds": round(elapsed_seconds, 3),
                "lines_per_second": round(lps, 1),
            },
        )

    def emit_finding(self, finding: Finding) -> TelemetryEvent:
        return self.emit(
            event_type="threat_detected",
            metrics={"severity_weight": 4 if finding.severity == "CRITICAL" else 3 if finding.severity == "HIGH" else 2},
            details={
                "rule_id": finding.rule_id,
                "attack_type": finding.attack_type,
                "severity": finding.severity,
                "ip": finding.ip,
                "mitre_attack_id": finding.metadata.get("mitre_attack_id"),
            },
        )

    def emit_scan_complete(
        self,
        stats: ParserStats,
        findings_count: int,
        incidents_count: int,
    ) -> TelemetryEvent:
        return self.emit(
            event_type="scan_completed",
            metrics={
                "total_lines": stats.total_lines,
                "parsed_lines": stats.parsed_lines,
                "malformed_lines": stats.malformed_lines,
                "duration_seconds": round(stats.duration_seconds, 3),
                "lines_per_second": round(stats.lines_per_second, 1),
                "total_findings": findings_count,
                "total_incidents": incidents_count,
            },
        )

    def close(self) -> None:
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
