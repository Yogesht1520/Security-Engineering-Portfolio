"""SQL Injection detection module using data-driven YAML rule patterns."""
import re
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple, Union

from ..models import Finding, LogEntry
from .base import BaseDetector


def multi_url_decode(value: str, max_rounds: int = 3) -> str:
    """Recursively decode URL-encoded values to uncover double/triple encoding evasion."""
    current = value
    for _ in range(max_rounds):
        try:
            decoded = urllib.parse.unquote_plus(current)
            if decoded == current:
                break
            current = decoded
        except Exception:
            break
    return current


class SQLiDetector(BaseDetector):
    """Detects SQL Injection payloads in requests and referrers."""

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        if config_path is None:
            # Default to bundled rules
            config_path = Path(__file__).resolve().parent.parent.parent / "rules" / "sqli.yaml"
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
                except re.error as e:
                    continue

    def process(self, entry: LogEntry) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []
        raw_path = entry.path or ""
        decoded_path = multi_url_decode(raw_path)

        targets = [
            ("URI Path", raw_path),
            ("Decoded URI Path", decoded_path),
        ]

        if entry.referrer and entry.referrer != "-":
            raw_ref = entry.referrer
            decoded_ref = multi_url_decode(raw_ref)
            targets.extend([
                ("Referrer Header", raw_ref),
                ("Decoded Referrer Header", decoded_ref),
            ])

        for rule, compiled in self.compiled_rules:
            matched = False
            for location_label, text in targets:
                match = compiled.search(text)
                if match:
                    findings.append(
                        Finding(
                            rule_id=rule.get("id", "SQLI-001"),
                            severity=rule.get("severity", "HIGH"),
                            attack_type=self.config.get("attack_type", "SQL Injection"),
                            ip=entry.ip,
                            timestamp=entry.timestamp,
                            evidence=match.group(0),
                            description=rule.get("description", "SQL Injection pattern detected."),
                            location=location_label,
                            metadata={
                                "mitre_attack_id": rule.get("mitre_attack_id", "T1190"),
                                "rule_name": rule.get("name", "SQL Injection Rule"),
                                "line_number": entry.line_number,
                                "matched_payload": text,
                            },
                        )
                    )
                    matched = True
                    break  # Avoid duplicate findings per rule on same entry
            if matched:
                continue

        return findings
