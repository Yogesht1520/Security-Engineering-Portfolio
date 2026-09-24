"""Tests for Rule Schema Validation and Report JSON Schema compliance."""
import json
from pathlib import Path
import pytest

from analyzer.detectors.base import RuleValidationError
from analyzer.detectors.schema import (
    validate_pattern_rules,
    validate_threshold_rules,
)
from analyzer.models import Finding, ParserStats
from analyzer.report import ReportBuilder


def test_valid_pattern_rules_passes():
    config = {
        "name": "Test Pattern Rules",
        "version": "1.0.0",
        "attack_type": "Test",
        "description": "Test descriptions",
        "rules": [
            {
                "id": "TEST-001",
                "name": "Test Rule",
                "severity": "HIGH",
                "mitre_attack_id": "T1190",
                "pattern": "(?i)select",
                "description": "SQL match",
            }
        ],
    }
    # Should not raise
    validate_pattern_rules(config)


def test_invalid_rule_id_fails():
    config = {
        "name": "Test Rules",
        "attack_type": "Test",
        "rules": [
            {
                "id": "invalid id with spaces!",
                "name": "Test Rule",
                "severity": "HIGH",
                "pattern": "test",
            }
        ],
    }
    with pytest.raises(RuleValidationError) as exc:
        validate_pattern_rules(config)
    assert "Must match pattern" in str(exc.value)


def test_invalid_severity_fails():
    config = {
        "name": "Test Rules",
        "attack_type": "Test",
        "rules": [
            {
                "id": "RULE-001",
                "name": "Test Rule",
                "severity": "SUPER_CRITICAL_NOT_VALID",
                "pattern": "test",
            }
        ],
    }
    with pytest.raises(RuleValidationError) as exc:
        validate_pattern_rules(config)
    assert "invalid severity" in str(exc.value)


def test_invalid_mitre_id_fails():
    config = {
        "name": "Test Rules",
        "attack_type": "Test",
        "rules": [
            {
                "id": "RULE-001",
                "name": "Test Rule",
                "severity": "HIGH",
                "mitre_attack_id": "NOT_A_MITRE_ID",
                "pattern": "test",
            }
        ],
    }
    with pytest.raises(RuleValidationError) as exc:
        validate_pattern_rules(config)
    assert "invalid mitre_attack_id" in str(exc.value)


def test_duplicate_rule_id_fails():
    config = {
        "name": "Test Rules",
        "attack_type": "Test",
        "rules": [
            {"id": "RULE-001", "name": "First", "pattern": "a"},
            {"id": "RULE-001", "name": "Second duplicate", "pattern": "b"},
        ],
    }
    with pytest.raises(RuleValidationError) as exc:
        validate_pattern_rules(config)
    assert "Duplicate rule ID" in str(exc.value)


def test_threshold_validation_rules():
    good_config = {
        "name": "Brute Force",
        "attack_type": "Brute Force",
        "rule_id": "BRUTE-001",
        "severity": "HIGH",
        "mitre_attack_id": "T1110",
        "window_seconds": 60,
        "threshold_count": 10,
    }
    validate_threshold_rules(good_config)

    bad_config = dict(good_config)
    bad_config["window_seconds"] = -5
    with pytest.raises(RuleValidationError) as exc:
        validate_threshold_rules(bad_config)
    assert "positive integer" in str(exc.value)


def test_json_report_schema_fields():
    """Verify that JSON output contains schema_version and required top-level keys."""
    builder = ReportBuilder(
        findings=[],
        stats=ParserStats(total_lines=10, parsed_lines=10),
        log_source="test.log",
        title="Schema Test Report",
    )
    json_str = builder.render_json()
    data = json.loads(json_str)

    assert data["schema_version"] == "1.0.0"
    assert "$schema" in data
    assert "summary" in data
    assert "incidents" in data
    assert "top_offenders" in data
    assert "findings" in data
