"""Authentication brute-force detector using sliding time-windows."""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple, Union

from ..models import Finding, LogEntry
from .base import BaseDetector, RuleValidationError
from .schema import validate_threshold_rules


class BruteForceDetector(BaseDetector):
    """Detects repeated failed authentication attempts within a sliding time window."""

    def __init__(self, config_path: Optional[Union[str, Path]] = None, strict: bool = True):
        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent.parent / "rules" / "bruteforce.yaml"
        super().__init__(config_path=config_path, strict=strict)

        if self.strict and self.config:
            validate_threshold_rules(self.config, self.config_path)

        self.window_seconds = int(self.config.get("window_seconds", 60))
        self.threshold = int(self.config.get("threshold_count", 10))
        self.target_endpoints = [ep.lower() for ep in self.config.get("target_endpoints", [])]
        self.target_statuses = set(self.config.get("target_status_codes", [401, 403, 429]))

        # State storage: ip -> deque of (timestamp, path, status)
        self.ip_history: Dict[str, Deque[Tuple[datetime, str, int]]] = defaultdict(deque)
        # Tracking alerts to avoid spamming findings for every single subsequent request in same window
        self.last_alert_time: Dict[str, datetime] = {}

    def reset(self) -> None:
        self.ip_history.clear()
        self.last_alert_time.clear()

    def _is_auth_endpoint(self, path: str) -> bool:
        norm_path = (path or "").split("?")[0].lower()
        return any(norm_path.endswith(ep) or ep in norm_path for ep in self.target_endpoints)

    def process(self, entry: LogEntry) -> List[Finding]:
        if not self.enabled:
            return []

        # Check if entry targets an auth endpoint with a failure/monitored status
        if entry.status not in self.target_statuses or not self._is_auth_endpoint(entry.path):
            return []

        history = self.ip_history[entry.ip]
        current_time = entry.timestamp
        cutoff_time = current_time - timedelta(seconds=self.window_seconds)

        # Evict timestamps older than the sliding window
        while history and history[0][0] < cutoff_time:
            history.popleft()

        history.append((current_time, entry.path, entry.status))

        # Check threshold
        if len(history) >= self.threshold:
            # Check if we already alerted on this IP within the recent window
            last_alert = self.last_alert_time.get(entry.ip)
            if last_alert is None or (current_time - last_alert).total_seconds() >= self.window_seconds:
                self.last_alert_time[entry.ip] = current_time
                count = len(history)
                desc_template = self.config.get(
                    "description_template",
                    "Detected {count} failed requests to auth endpoint '{endpoint}' within {window_seconds}s from IP {ip}."
                )
                description = desc_template.format(
                    count=count,
                    endpoint=entry.path.split("?")[0],
                    window_seconds=self.window_seconds,
                    ip=entry.ip,
                )

                return [
                    Finding(
                        rule_id=self.config.get("rule_id", "BRUTE-001"),
                        severity=self.config.get("severity", "HIGH"),
                        attack_type=self.config.get("attack_type", "Brute-Force Attack"),
                        ip=entry.ip,
                        timestamp=entry.timestamp,
                        evidence=f"{count} failed auth attempts in {self.window_seconds}s window (latest: {entry.method} {entry.path} -> {entry.status})",
                        description=description,
                        location="Authentication Endpoint",
                        metadata={
                            "mitre_attack_id": self.config.get("mitre_attack_id", "T1110"),
                            "failed_attempts": count,
                            "window_seconds": self.window_seconds,
                            "line_number": entry.line_number,
                            "target_endpoint": entry.path,
                        },
                    )
                ]

        return []
