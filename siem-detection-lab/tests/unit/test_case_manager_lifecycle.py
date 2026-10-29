#!/usr/bin/env python3
"""
test_case_manager_lifecycle.py — Unit Tests for Case Lifecycle & Privileged Reopen Governance

Verifies:
1. Standard lifecycle progression: open -> investigating -> contained -> closed.
2. State Machine Enforcement: Transition out of closed via standard --transition fails closed.
3. Privileged Reopen Governance:
   - Missing authorizer -> REJECTED.
   - Insufficient justification (< 10 chars) -> REJECTED.
   - Valid authorizer + justification -> ACCEPTED, SHA-256 seal computed and recorded.
4. Schema conformance of the resulting case file.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

def test_case_lifecycle_and_reopen():
    print("=" * 65)
    print("   Incident Case Lifecycle & Privileged Reopen Unit Suite    ")
    print("=" * 65)

    # 1. Create a synthetic test case directly
    cases_dir = REPO_ROOT / "incident_management" / "cases"
    test_case_id = "CASE-2099-999"
    test_case_path = cases_dir / f"{test_case_id}.json"

    dummy_case = {
        "case_id": test_case_id,
        "title": "Unit Test Case Lifecycle",
        "status": "investigating",
        "severity": "medium",
        "opened_at": "2099-01-01T00:00:00Z",
        "closed_at": None,
        "source_ip": "198.51.100.222",
        "geo": {"country": "Testland", "city": "Testcity", "asn": "AS9999", "isp": "TestISP"},
        "reputation": {"abuseipdb_score": 0, "total_reports": 0, "last_reported_at": None},
        "wazuh_alert_ids": [],
        "target_users": ["root"],
        "timeline": [{"timestamp": "2099-01-01T00:00:00Z", "event": "Test case initialized"}],
        "reopen_records": [],
        "containment_actions": [],
        "evidence_preserved": True,
        "analyst": "Automated Tester",
        "root_cause": "",
        "lessons_learned": ""
    }

    try:
        with open(test_case_path, "w", encoding="utf-8") as f:
            json.dump(dummy_case, f, indent=2)

        # Step A: Transition investigating -> contained
        cmd_trans1 = [sys.executable, "incident_management/case_manager.py", "--transition", test_case_id, "contained"]
        res = subprocess.run(cmd_trans1, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 0, f"Transition to contained failed: {res.stderr}"
        print("  [✓] Standard transition: INVESTIGATING -> CONTAINED succeeded.")

        # Step B: Transition contained -> closed
        cmd_trans2 = [sys.executable, "incident_management/case_manager.py", "--close", test_case_id, "Investigation confirmed benign scanner"]
        res = subprocess.run(cmd_trans2, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 0, f"Close failed: {res.stderr}"
        print("  [✓] Standard transition: CONTAINED -> CLOSED succeeded.")

        # Step C: Negative Test — Attempt unprivileged transition out of closed
        cmd_illegal = [sys.executable, "incident_management/case_manager.py", "--transition", test_case_id, "open"]
        res = subprocess.run(cmd_illegal, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode != 0, "Expected non-zero exit code on unprivileged transition from closed!"
        assert "Disallowed transition out of terminal state" in res.stdout or "Privileged Governance" in res.stdout
        print("  [✓] Negative Test PASSED: Unprivileged transition from CLOSED correctly blocked.")

        # Step D: Negative Test — Attempt reopen without authorizer
        cmd_reopen_no_auth = [sys.executable, "incident_management/case_manager.py", "--reopen", test_case_id, "--justification", "Valid operational reason here"]
        res = subprocess.run(cmd_reopen_no_auth, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode != 0, "Expected failure when --authorizer is missing!"
        print("  [✓] Negative Test PASSED: Reopen without authorizer correctly rejected.")

        # Step E: Negative Test — Attempt reopen with trivial justification
        cmd_reopen_short_just = [sys.executable, "incident_management/case_manager.py", "--reopen", test_case_id, "--authorizer", "SOC Lead", "--justification", "short"]
        res = subprocess.run(cmd_reopen_short_just, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode != 0, "Expected failure when justification is < 10 chars!"
        print("  [✓] Negative Test PASSED: Reopen with trivial justification correctly rejected.")

        # Step F: Positive Test — Authorized Privileged Reopen
        cmd_reopen_valid = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "Incident Commander Alice",
            "--justification", "New correlated authentication telemetry discovered in honeypot auth.log"
        ]
        res = subprocess.run(cmd_reopen_valid, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 0, f"Privileged reopen failed: {res.stderr}\n{res.stdout}"
        assert "REOPENED to status INVESTIGATING" in res.stdout
        print("  [✓] Positive Test PASSED: Privileged reopen succeeded with cryptographic audit trail.")

        # Step G: Verify persisted case structure & schema
        with open(test_case_path, "r", encoding="utf-8") as f:
            updated_case = json.load(f)

        assert updated_case["status"] == "investigating"
        assert updated_case["closed_at"] is None
        assert len(updated_case["reopen_records"]) == 1
        rec = updated_case["reopen_records"][0]
        assert rec["authorizer"] == "Incident Commander Alice"
        assert len(rec["prior_state_sha256"]) == 64
        print(f"  [✓] State seal verified: {rec['prior_state_sha256'][:16]}...")

    finally:
        if test_case_path.exists():
            test_case_path.unlink()

    print("=" * 65)
    print("[+] All case manager lifecycle and reopen assertions PASSED.")
    print("=" * 65)

if __name__ == "__main__":
    test_case_lifecycle_and_reopen()

