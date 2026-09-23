"""Vulnerability scanner and suspicious User-Agent fingerprint detector."""
import re
from pathlib import Path
from typing import List, Optional, Tuple, Union

from ..models import Finding, LogEntry
from .base import BaseDetector


class ScannerUADetector(BaseDetector):
    """Detects security scanners, recon tools, and abnormal User-Agent headers."""

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent.parent / "rules" / "scanner_ua.yaml"
        super().__init__(config_path=config_path)
        self.compiled_rules: List[Tuple[dict, re.Pattern]] = []
        self._compile_rules()

    def _compile_rules(self) -> None:
        self.compiled_rules.clear()
        rules = self.config.get("rules", [])
        for rule in rules:
            pattern = rule.get("pattern")
            if pattern:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self.compiled_rules.append((rule, compiled))
                except re.error:
                    continue

    def process(self, entry: LogEntry) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []
        ua = entry.user_agent

        # Check for missing/empty User-Agent
        flag_empty = self.config.get("flag_empty_user_agent", False)
        if flag_empty and (not ua or ua.strip() == "-" or ua.strip() == ""):
            findings.append(
                Finding(
                    rule_id="SCAN-000",
                    severity=self.config.get("empty_ua_severity", "LOW"),
                    attack_type=self.config.get("attack_type", "Scanner Reconnaissance"),
                    ip=entry.ip,
                    timestamp=entry.timestamp,
                    evidence="User-Agent: (empty/missing)",
                    description="Request sent with missing or stripped User-Agent header.",
                    location="User-Agent Header",
                    metadata={
                        "mitre_attack_id": "T1595",
                        "rule_name": "Missing User-Agent Header",
                        "line_number": entry.line_number,
                    },
                )
            )
            return findings

        if not ua or ua == "-":
            return []

        for rule, compiled in self.compiled_rules:
            match = compiled.search(ua)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule.get("id", "SCAN-001"),
                        severity=rule.get("severity", "HIGH"),
                        attack_type=self.config.get("attack_type", "Scanner Reconnaissance"),
                        ip=entry.ip,
                        timestamp=entry.timestamp,
                        evidence=match.group(0),
                        description=rule.get("description", "Vulnerability scanner fingerprint identified."),
                        location="User-Agent Header",
                        metadata={
                            "mitre_attack_id": rule.get("mitre_attack_id", "T1595"),
                            "rule_name": rule.get("name", "Scanner Fingerprint Rule"),
                            "line_number": entry.line_number,
                            "user_agent_full": ua,
                        },
                    )
                )

        return findings
