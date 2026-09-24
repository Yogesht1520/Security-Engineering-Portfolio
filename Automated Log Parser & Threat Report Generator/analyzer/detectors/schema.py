"""Schema validation for YAML detection rules."""
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import RuleValidationError

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
RULE_ID_PATTERN = re.compile(r"^[A-Z0-9_-]+$")
MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def validate_rule_metadata(config: Dict[str, Any], file_path: Optional[Path] = None) -> None:
    """Validate top-level metadata across all detection rule files."""
    prefix = f"[{file_path.name}] " if file_path else ""

    required_keys = ["name", "attack_type"]
    for key in required_keys:
        val = config.get(key)
        if not val or not isinstance(val, str):
            raise RuleValidationError(f"{prefix}Missing or invalid required top-level string field '{key}'.")


def validate_pattern_rules(
    config: Dict[str, Any],
    file_path: Optional[Path] = None,
    detector_label: str = "Detection",
) -> None:
    """Validate pattern-based signature rules (e.g. SQLi, Traversal, Scanner UA)."""
    prefix = f"[{file_path.name}] " if file_path else ""
    validate_rule_metadata(config, file_path)

    rules = config.get("rules")
    if not isinstance(rules, list) or len(rules) == 0:
        raise RuleValidationError(f"{prefix}Field 'rules' must be a non-empty list of rule objects.")

    seen_ids = set()
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise RuleValidationError(f"{prefix}Rule #{idx+1} is not a valid dictionary object.")

        rule_id = rule.get("id")
        if not rule_id or not isinstance(rule_id, str) or not RULE_ID_PATTERN.match(rule_id):
            raise RuleValidationError(
                f"{prefix}Rule #{idx+1} has invalid or missing 'id': '{rule_id}'. Must match pattern '^[A-Z0-9_-]+$'."
            )

        if rule_id in seen_ids:
            raise RuleValidationError(f"{prefix}Duplicate rule ID '{rule_id}' detected.")
        seen_ids.add(rule_id)

        name = rule.get("name")
        if not name or not isinstance(name, str):
            raise RuleValidationError(f"{prefix}Rule '{rule_id}' is missing required 'name' string.")

        severity = rule.get("severity")
        if severity and str(severity).upper() not in VALID_SEVERITIES:
            raise RuleValidationError(
                f"{prefix}Rule '{rule_id}' has invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}"
            )

        mitre_id = rule.get("mitre_attack_id")
        if mitre_id and not MITRE_ID_PATTERN.match(str(mitre_id)):
            raise RuleValidationError(
                f"{prefix}Rule '{rule_id}' has invalid mitre_attack_id '{mitre_id}'. Must match 'T####' or 'T####.###'."
            )

        pattern = rule.get("pattern")
        if not pattern or not isinstance(pattern, str):
            raise RuleValidationError(f"{prefix}{detector_label} rule {rule_id} is missing required 'pattern' field.")

        try:
            re.compile(pattern)
        except re.error as e:
            raise RuleValidationError(
                f"{prefix}Failed to compile regex for {detector_label} rule {rule_id} ('{pattern}'): {e}"
            ) from e


def validate_threshold_rules(
    config: Dict[str, Any],
    file_path: Optional[Path] = None,
    detector_label: str = "Threshold",
) -> None:
    """Validate threshold / sliding-window rule files (e.g. Brute Force, Status Burst)."""
    prefix = f"[{file_path.name}] " if file_path else ""
    validate_rule_metadata(config, file_path)

    rule_id = config.get("rule_id")
    if not rule_id or not isinstance(rule_id, str) or not RULE_ID_PATTERN.match(rule_id):
        raise RuleValidationError(f"{prefix}Missing or invalid 'rule_id': '{rule_id}'.")

    severity = config.get("severity")
    if severity and str(severity).upper() not in VALID_SEVERITIES:
        raise RuleValidationError(
            f"{prefix}Invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}"
        )

    mitre_id = config.get("mitre_attack_id")
    if mitre_id and not MITRE_ID_PATTERN.match(str(mitre_id)):
        raise RuleValidationError(
            f"{prefix}Invalid mitre_attack_id '{mitre_id}'. Must match 'T####' or 'T####.###'."
        )

    window = config.get("window_seconds")
    if not isinstance(window, int) or window <= 0:
        raise RuleValidationError(f"{prefix}Field 'window_seconds' must be a positive integer, got: {window}")

    threshold = config.get("threshold_count")
    if not isinstance(threshold, int) or threshold <= 0:
        raise RuleValidationError(f"{prefix}Field 'threshold_count' must be a positive integer, got: {threshold}")
