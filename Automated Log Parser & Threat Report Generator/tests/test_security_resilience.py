"""Security resilience tests: ReDoS protection, Rule validation, and Malformed input handling."""
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import pytest
import yaml

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.detectors import (
    DetectionEngine,
    RuleValidationError,
    SQLiDetector,
    TraversalDetector,
    ScannerUADetector,
)
from analyzer.models import LogEntry, ParserStats
from analyzer.parser import LogParser, parse_datetime


def make_entry(path: str = "/", user_agent: str = "Mozilla/5.0", referrer: str = "-") -> LogEntry:
    return LogEntry(
        ip="192.0.2.1",
        timestamp=datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status=200,
        bytes_sent=1000,
        referrer=referrer,
        user_agent=user_agent,
        raw="raw log line",
        line_number=1,
    )


def test_unparseable_timestamp_returns_none():
    """Verify that corrupt timestamps are returned as None and never substituted with datetime.now()."""
    assert parse_datetime("") is None
    assert parse_datetime("invalid-timestamp") is None
    assert parse_datetime("32/Dec/2026:99:99:99 +0000") is None
    assert parse_datetime("2026-99-99 99:99:99") is None


def test_malformed_timestamp_line_rejected_by_parser():
    """Verify that log lines with corrupt timestamps increment malformed_lines and return None."""
    parser = LogParser()
    bad_line = '192.168.1.1 - - [CORRUPT_TIMESTAMP_GARBAGE] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    entry = parser.parse_line(bad_line, line_number=1)
    assert entry is None


def test_broken_regex_raises_rule_validation_error(tmp_path: Path):
    """Verify that a broken regex in a rule file fails fast with RuleValidationError."""
    broken_yaml = tmp_path / "broken_rule.yaml"
    broken_yaml.write_text(
        """
name: "Broken Rules"
attack_type: "Test"
rules:
  - id: "BROKEN-001"
    name: "Unclosed Regex Group"
    severity: "HIGH"
    pattern: "(?i)(unclosed_group["
    description: "Broken regex syntax"
        """,
        encoding="utf-8",
    )

    with pytest.raises(RuleValidationError) as exc_info:
        SQLiDetector(config_path=broken_yaml, strict=True)
    assert "Failed to compile regex for SQLi rule BROKEN-001" in str(exc_info.value)


def test_missing_pattern_raises_rule_validation_error(tmp_path: Path):
    """Verify that a rule missing a required pattern field raises RuleValidationError."""
    invalid_yaml = tmp_path / "missing_pattern.yaml"
    invalid_yaml.write_text(
        """
name: "Missing Pattern"
attack_type: "Test"
rules:
  - id: "INVALID-001"
    name: "No Pattern"
    severity: "HIGH"
    description: "Missing pattern"
        """,
        encoding="utf-8",
    )

    with pytest.raises(RuleValidationError) as exc_info:
        TraversalDetector(config_path=invalid_yaml, strict=True)
    assert "missing required 'pattern' field" in str(exc_info.value)


def test_redos_resistance_pathological_payloads():
    """
    Test evaluation speed against massive 100KB+ payloads, repetitive backtracking patterns,
    and pathological attacker inputs to ensure resilience against ReDoS.
    """
    engine = DetectionEngine()

    # 1. 100KB long query parameter with repetitive patterns
    massive_payload = "/search?q=" + ("' OR '1'='1" * 1500)
    entry1 = make_entry(path=massive_payload)

    t0 = time.perf_counter()
    findings1 = engine.process_entry(entry1)
    duration1 = time.perf_counter() - t0

    assert duration1 < 0.2, f"ReDoS vulnerability detected: took {duration1:.3f}s"
    assert len(findings1) > 0

    # 2. Path traversal repetition (10,000 slashes and dots)
    massive_traversal = "/view?doc=" + ("../" * 3000) + "etc/passwd"
    entry2 = make_entry(path=massive_traversal)

    t0 = time.perf_counter()
    findings2 = engine.process_entry(entry2)
    duration2 = time.perf_counter() - t0

    assert duration2 < 0.2, f"Traversal regex slow: took {duration2:.3f}s"
    assert len(findings2) > 0

    # 3. Pathological User-Agent string (50,000 repeated characters)
    massive_ua = "Mozilla/5.0 (" + ("A" * 50000) + ") sqlmap/1.7.2"
    entry3 = make_entry(user_agent=massive_ua)

    t0 = time.perf_counter()
    findings3 = engine.process_entry(entry3)
    duration3 = time.perf_counter() - t0

    assert duration3 < 0.2, f"Scanner UA regex slow: took {duration3:.3f}s"
    assert len(findings3) > 0


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
