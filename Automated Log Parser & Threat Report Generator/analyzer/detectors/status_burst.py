"""Status code burst anomaly detector using sliding time-windows."""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple, Union

from ..models import Finding, LogEntry
from .base import BaseDetector, RuleValidationError
from .schema import validate_threshold_rules


class StatusBurstDetector(BaseDetector):
    """Detects rapid bursts of anomalous HTTP status codes (e.g., 404/403 fuzzing bursts)."""

    def __init__(self, config_path: Optional[Union[str, Path]] = None, strict: bool = True):
        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent.parent / "rules" / "status_burst.yaml"
        super().__init__(config_path=config_path, strict=strict)

        if self.strict and self.config:
            validate_threshold_rules(self.config, self.config_path)

        self.window_seconds = int(self.config.get("window_seconds", 30))
        self.threshold = int(self.config.get("threshold_count", 20))
        self.monitored_statuses = set(self.config.get("monitored_status_codes", [400, 401, 403, 404, 500, 502, 503]))

        self.ip_history: Dict[str, Deque[Tuple[datetime, str, int]]] = defaultdict(deque)
        self.last_alert_time: Dict[str, datetime] = {}

    def reset(self) -> None:
        self.ip_history.clear()
        self.last_alert_time.clear()

    def process(self, entry: LogEntry) -> List[Finding]:
        if not self.enabled:
            return []

        if entry.status not in self.monitored_statuses:
            return []

        history = self.ip_history[entry.ip]
        current_time = entry.timestamp
        cutoff_time = current_time - timedelta(seconds=self.window_seconds)

        while history and history[0][0] < cutoff_time:
            history.popleft()

        history.append((current_time, entry.path, entry.status))

        if len(history) >= self.threshold:
            last_alert = self.last_alert_time.get(entry.ip)
            if last_alert is None or (current_time - last_alert).total_seconds() >= self.window_seconds:
                self.last_alert_time[entry.ip] = current_time
                count = len(history)
                desc_template = self.config.get(
                    "description_template",
                    "Detected burst of {count} anomalous HTTP responses within {window_seconds}s from IP {ip}."
                )
                description = desc_template.format(
                    count=count,
                    status_types="4xx/5xx",
                    window_seconds=self.window_seconds,
                    ip=entry.ip,
                )

                return [
                    Finding(
                        rule_id=self.config.get("rule_id", "BURST-001"),
                        severity=self.config.get("severity", "MEDIUM"),
                        attack_type=self.config.get("attack_type", "Status-Code Burst Anomaly"),
                        ip=entry.ip,
                        timestamp=entry.timestamp,
                        evidence=f"{count} anomalous HTTP {entry.status} errors in {self.window_seconds}s window (latest path: {entry.path})",
                        description=description,
                        location="HTTP Status Monitor",
                        metadata={
                            "mitre_attack_id": self.config.get("mitre_attack_id", "T1595.003"),
                            "error_count": count,
                            "window_seconds": self.window_seconds,
                            "line_number": entry.line_number,
                        },
                    )
                ]

        return []
