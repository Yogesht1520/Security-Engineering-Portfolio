"""Path and directory traversal detection module using YAML rules."""
import re
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple, Union

from ..models import Finding, LogEntry
from .base import BaseDetector, RuleValidationError
from .schema import validate_pattern_rules
from .sqli import multi_url_decode


class TraversalDetector(BaseDetector):
    """Detects Directory and Path Traversal attack sequences."""

    def __init__(self, config_path: Optional[Union[str, Path]] = None, strict: bool = True):
        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent.parent / "rules" / "traversal.yaml"
        super().__init__(config_path=config_path, strict=strict)
        self.compiled_rules: List[Tuple[dict, re.Pattern]] = []
        self._compile_rules()

    def _compile_rules(self) -> None:
        self.compiled_rules.clear()
        if self.strict and self.config:
            validate_pattern_rules(self.config, self.config_path, detector_label="Traversal")
        rules = self.config.get("rules", [])
        for rule in rules:
            rule_id = rule.get("id", "UNKNOWN-TRAV")
            pattern = rule.get("pattern")
            if not pattern:
                msg = f"Traversal rule {rule_id} is missing required 'pattern' field."
                if self.strict:
                    raise RuleValidationError(msg)
                continue
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self.compiled_rules.append((rule, compiled))
            except re.error as e:
                msg = f"Failed to compile regex for Traversal rule {rule_id} ('{pattern}'): {e}"
                if self.strict:
                    raise RuleValidationError(msg) from e

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

        for rule, compiled in self.compiled_rules:
            for location_label, text in targets:
                match = compiled.search(text)
                if match:
                    findings.append(
                        Finding(
                            rule_id=rule.get("id", "TRAV-001"),
                            severity=rule.get("severity", "HIGH"),
                            attack_type=self.config.get("attack_type", "Path Traversal"),
                            ip=entry.ip,
                            timestamp=entry.timestamp,
                            evidence=match.group(0),
                            description=rule.get("description", "Path traversal pattern detected."),
                            location=location_label,
                            metadata={
                                "mitre_attack_id": rule.get("mitre_attack_id", "T1083"),
                                "rule_name": rule.get("name", "Path Traversal Rule"),
                                "line_number": entry.line_number,
                                "matched_payload": text,
                            },
                        )
                    )
                    break

        return findings
