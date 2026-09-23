"""Unit tests and ground-truth validation for detection rules and engines."""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from analyzer.detectors import (
    DetectionEngine,
    SQLiDetector,
    TraversalDetector,
    ScannerUADetector,
    BruteForceDetector,
    StatusBurstDetector,
)
from analyzer.models import LogEntry
from analyzer.parser import LogParser
from sample_logs.generate_demo_log import generate_demo_dataset


def make_entry(
    ip: str = "127.0.0.1",
    method: str = "GET",
    path: str = "/",
    status: int = 200,
    user_agent: str = "Mozilla/5.0",
    referrer: str = "-",
    line_number: int = 1,
    dt: datetime = None,
) -> LogEntry:
    return LogEntry(
        ip=ip,
        timestamp=dt or datetime.now(timezone.utc),
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        bytes_sent=1000,
        referrer=referrer,
        user_agent=user_agent,
        raw="test line",
        line_number=line_number,
    )


def test_sqli_detector_matches():
    detector = SQLiDetector()

    # Positive matches
    entry1 = make_entry(path="/products?id=1%20UNION%20SELECT%20null,pass%20FROM%20users--")
    f1 = detector.process(entry1)
    assert len(f1) >= 1
    assert any(f.rule_id == "SQLI-001" for f in f1)

    entry2 = make_entry(path="/search?q=admin'%20OR%20'1'='1")
    f2 = detector.process(entry2)
    assert len(f2) >= 1
    assert any(f.rule_id == "SQLI-002" for f in f2)

    entry3 = make_entry(path="/api?id=1%20AND%20SLEEP(5)")
    f3 = detector.process(entry3)
    assert len(f3) >= 1
    assert any(f.rule_id == "SQLI-003" for f in f3)

    # Benign paths
    entry_benign = make_entry(path="/products/books-and-music?id=123")
    assert len(detector.process(entry_benign)) == 0


def test_traversal_detector_matches():
    detector = TraversalDetector()

    # Standard and encoded climbing
    entry1 = make_entry(path="/view?file=../../../../etc/passwd")
    f1 = detector.process(entry1)
    assert len(f1) >= 1
    assert any(f.rule_id in ("TRAV-001", "TRAV-002") for f in f1)

    # Double-encoded traversal
    entry2 = make_entry(path="/static/doc?name=..%252e%252e%252fwin.ini")
    f2 = detector.process(entry2)
    assert len(f2) >= 1
    assert any(f.rule_id in ("TRAV-001", "TRAV-003") for f in f2)

    # Benign
    entry_benign = make_entry(path="/assets/images/preview.png")
    assert len(detector.process(entry_benign)) == 0


def test_scanner_ua_detector_matches():
    detector = ScannerUADetector()

    # sqlmap
    f1 = detector.process(make_entry(user_agent="sqlmap/1.7.2#stable"))
    assert len(f1) == 1
    assert f1[0].rule_id == "SCAN-001"

    # Nikto
    f2 = detector.process(make_entry(user_agent="Mozilla/5.00 (Nikto/2.1.6)"))
    assert len(f2) == 1
    assert f2[0].rule_id == "SCAN-002"

    # DirBuster
    f3 = detector.process(make_entry(user_agent="DirBuster-1.0.0-RC1"))
    assert len(f3) == 1
    assert f3[0].rule_id == "SCAN-003"

    # Missing UA
    f4 = detector.process(make_entry(user_agent="-"))
    assert len(f4) == 1
    assert f4[0].rule_id == "SCAN-000"

    # Normal browser
    f_benign = detector.process(
        make_entry(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
    )
    assert len(f_benign) == 0


def test_bruteforce_detector_sliding_window():
    detector = BruteForceDetector()
    detector.reset()

    base_time = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    ip = "192.0.2.100"

    # 9 attempts -> below threshold (10)
    for i in range(9):
        dt = datetime.fromtimestamp(base_time.timestamp() + (i * 2), tz=timezone.utc)
        findings = detector.process(make_entry(ip=ip, path="/wp-login.php", status=401, dt=dt))
        assert len(findings) == 0

    # 10th attempt -> triggers brute force alert
    dt10 = datetime.fromtimestamp(base_time.timestamp() + 18, tz=timezone.utc)
    findings10 = detector.process(make_entry(ip=ip, path="/wp-login.php", status=401, dt=dt10))
    assert len(findings10) == 1
    assert findings10[0].rule_id == "BRUTE-001"
    assert findings10[0].attack_type == "Brute-Force Attack"


def test_status_burst_detector_sliding_window():
    detector = StatusBurstDetector()
    detector.reset()

    base_time = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    ip = "192.0.2.200"

    # 19 errors -> below threshold (20)
    for i in range(19):
        dt = datetime.fromtimestamp(base_time.timestamp() + i, tz=timezone.utc)
        findings = detector.process(make_entry(ip=ip, path=f"/fuzz_{i}", status=404, dt=dt))
        assert len(findings) == 0

    # 20th error -> triggers status burst
    dt20 = datetime.fromtimestamp(base_time.timestamp() + 19, tz=timezone.utc)
    findings20 = detector.process(make_entry(ip=ip, path="/fuzz_20", status=404, dt=dt20))
    assert len(findings20) == 1
    assert findings20[0].rule_id == "BURST-001"


def test_ground_truth_synthetic_log_assertions(tmp_path: Path):
    """
    End-to-end detection assertion: run parser and detection engine against
    synthetic demo log dataset and assert zero false negatives against known ground truth.
    """
    base_time = datetime(2026, 9, 24, 8, 0, 0, tzinfo=timezone.utc)
    lines, ground_truth = generate_demo_dataset(base_time)

    test_log = tmp_path / "ground_truth_test.log"
    with open(test_log, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

    parser = LogParser()
    engine = DetectionEngine()
    engine.reset()

    entries = list(parser.parse_stream(test_log))
    findings = engine.process_stream(entries)

    # Count detections by attack type
    counts_by_type = {
        "SQL Injection": 0,
        "Path Traversal": 0,
        "Scanner Reconnaissance": 0,
        "Brute-Force Attack": 0,
        "Status-Code Burst Anomaly": 0,
    }

    for f in findings:
        if f.attack_type in counts_by_type:
            counts_by_type[f.attack_type] += 1

    # Assert exact match or at least ground-truth threshold (0 false negatives)
    for attack_type, expected_count in ground_truth.items():
        detected = counts_by_type.get(attack_type, 0)
        assert (
            detected >= expected_count
        ), f"False negative on {attack_type}: expected >= {expected_count}, got {detected}"


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
