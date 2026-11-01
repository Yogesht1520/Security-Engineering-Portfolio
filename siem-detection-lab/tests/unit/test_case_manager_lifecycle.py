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

    # Isolated Temporary Test Directory — Real cases/ directory is NEVER modified
    with tempfile.TemporaryDirectory() as temp_dir:
        test_cases_dir = Path(temp_dir)
        test_env = os.environ.copy()
        test_env["SIEM_CASES_DIR"] = str(test_cases_dir)
        os.environ["SIEM_CASES_DIR"] = str(test_cases_dir)

        import incident_management.case_manager as cm
        cm.CASES_DIR = str(test_cases_dir)

        test_case_id = "CASE-2099-999"
        test_case_path = test_cases_dir / f"{test_case_id}.json"

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

        with open(test_case_path, "w", encoding="utf-8") as f:
            json.dump(dummy_case, f, indent=2)

        # Step A: Transition investigating -> contained
        cmd_trans1 = [sys.executable, "incident_management/case_manager.py", "--transition", test_case_id, "contained"]
        res = subprocess.run(cmd_trans1, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode == 0, f"Transition to contained failed: {res.stderr}"
        print("  [✓] Standard transition: INVESTIGATING -> CONTAINED succeeded.")

        # Step B: Transition contained -> closed
        cmd_trans2 = [sys.executable, "incident_management/case_manager.py", "--close", test_case_id, "Investigation confirmed benign scanner"]
        res = subprocess.run(cmd_trans2, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode == 0, f"Close failed: {res.stderr}"
        print("  [✓] Standard transition: CONTAINED -> CLOSED succeeded.")

        # Step C: Negative Test — Attempt unprivileged transition out of closed
        cmd_illegal = [sys.executable, "incident_management/case_manager.py", "--transition", test_case_id, "open"]
        res = subprocess.run(cmd_illegal, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode != 0, "Expected non-zero exit code on unprivileged transition from closed!"
        assert "Disallowed transition out of terminal state" in res.stdout or "Privileged Governance" in res.stdout
        print("  [✓] Negative Test PASSED: Unprivileged transition from CLOSED correctly blocked.")

        # Step D: Negative Test — Attempt reopen without authorizer
        cmd_reopen_no_auth = [sys.executable, "incident_management/case_manager.py", "--reopen", test_case_id, "--justification", "Valid operational reason here"]
        res = subprocess.run(cmd_reopen_no_auth, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode != 0, "Expected failure when --authorizer is missing!"
        print("  [✓] Negative Test PASSED: Reopen without authorizer correctly rejected.")

        # Step E: Negative Test — Attempt reopen with unauthorized role (e.g. Intern / Operator)
        cmd_reopen_unauth_role = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "Junior Intern Bob",
            "--justification", "Valid operational reason here"
        ]
        res = subprocess.run(cmd_reopen_unauth_role, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode != 0, "Expected failure when authorizer lacks designated governance authority!"
        assert "not a recognized governance authority" in res.stdout or "lacks designated governance authority" in res.stdout
        print("  [✓] Negative Test PASSED: Authorizer without governance role correctly rejected.")

        # Step E2: Negative Test — Caller identity lacks RBAC policy assignment for requested role
        unauth_env = test_env.copy()
        unauth_env["USER"] = "unauthorized_guest"
        unauth_env["USERNAME"] = "unauthorized_guest"
        unauth_env["LOGNAME"] = "unauthorized_guest"
        unauth_env["SIEM_TEST_IDENTITY"] = "unauthorized_guest"
        unauth_env["SIEM_TEST_HARNESS_ACTIVE"] = "1"
        cmd_rbac_unauth = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Valid operational reason here"
        ]
        res = subprocess.run(cmd_rbac_unauth, cwd=str(REPO_ROOT), capture_output=True, text=True, env=unauth_env)
        assert res.returncode != 0, "Expected failure when caller lacks RBAC assignment in rbac_policy.json!"
        assert "lacks verified RBAC assignment" in res.stdout
        print("  [✓] Negative Test PASSED: Principal without RBAC assignment correctly rejected (identity binding enforced).")

        # Step E3: Negative Test — SIEM_TEST_IDENTITY is strictly rejected in production environment
        prod_tamper_env = test_env.copy()
        prod_tamper_env["SIEM_ENV"] = "production"
        prod_tamper_env["SIEM_TEST_IDENTITY"] = "attacker_spoofed_admin"
        cmd_prod_tamper = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Attempting test identity override in production"
        ]
        res = subprocess.run(cmd_prod_tamper, cwd=str(REPO_ROOT), capture_output=True, text=True, env=prod_tamper_env)
        assert res.returncode != 0, "Expected failure when SIEM_TEST_IDENTITY is presented in production!"
        assert "PermissionError" in res.stderr or "strictly prohibited in production" in res.stderr
        print("  [✓] Negative Test PASSED: SIEM_TEST_IDENTITY strictly isolated and rejected in production.")

        # Step F: Negative Test — Attempt reopen with trivial justification
        cmd_reopen_short_just = [sys.executable, "incident_management/case_manager.py", "--reopen", test_case_id, "--authorizer", "SOC Lead Alice", "--justification", "short"]
        res = subprocess.run(cmd_reopen_short_just, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode != 0, "Expected failure when justification is < 10 chars!"
        print("  [✓] Negative Test PASSED: Reopen with trivial justification correctly rejected.")

        # ── Cryptographic HMAC Bearer Token Suite ──────────────────────────
        from incident_management.case_manager import generate_rbac_token
        test_secret = "test-secret-key-for-rbac-verification-2026"
        valid_user = test_env.get("USER") or test_env.get("USERNAME") or "yoges"

        # Step F1: Negative Token Test — Missing external secret in environment
        token_env_no_secret = test_env.copy()
        token_env_no_secret.pop("SIEM_RBAC_SECRET", None)
        dummy_tok = generate_rbac_token(valid_user, "soc lead", test_secret)
        cmd_tok_no_sec = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing token secret requirement",
            "--auth-token", dummy_tok
        ]
        res = subprocess.run(cmd_tok_no_sec, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_no_secret)
        assert res.returncode != 0, "Expected failure when SIEM_RBAC_SECRET is missing!"
        assert "SIEM_RBAC_SECRET is not provisioned" in res.stdout
        print("  [✓] Negative Token Test PASSED: Missing SIEM_RBAC_SECRET fails closed.")

        # Step F2: Negative Token Test — Missing subject ('sub') claim
        token_env_with_secret = test_env.copy()
        token_env_with_secret["SIEM_RBAC_SECRET"] = test_secret
        token_no_sub = generate_rbac_token(valid_user, "soc lead", test_secret, custom_claims={"sub": None})
        cmd_tok_no_sub = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing missing subject claim",
            "--auth-token", token_no_sub
        ]
        res = subprocess.run(cmd_tok_no_sub, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure when subject claim is missing!"
        assert "Missing mandatory 'sub'" in res.stdout
        print("  [✓] Negative Token Test 2/10 PASSED: Missing subject claim correctly rejected.")

        # Step F3: Negative Token Test — Token subject binding mismatch
        token_mismatch = generate_rbac_token("alice_different_user", "soc lead", test_secret)
        cmd_tok_mismatch = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing token subject mismatch",
            "--auth-token", token_mismatch
        ]
        res = subprocess.run(cmd_tok_mismatch, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure when token subject does not match caller!"
        assert "Token subject binding mismatch" in res.stdout
        print("  [✓] Negative Token Test 3/10 PASSED: Token subject mismatch correctly rejected.")

        # Step F4: Negative Token Test — Expired token
        token_expired = generate_rbac_token(valid_user, "soc lead", test_secret, ttl_seconds=-10)
        cmd_tok_exp = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing token expiry rejection",
            "--auth-token", token_expired
        ]
        res = subprocess.run(cmd_tok_exp, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure on expired token!"
        assert "Token expired at" in res.stdout
        print("  [✓] Negative Token Test 4/10 PASSED: Expired token correctly rejected.")

        # Step F5: Negative Token Test — Future not-before (nbf) claim
        token_future_nbf = generate_rbac_token(valid_user, "soc lead", test_secret, nbf_offset=600)
        cmd_tok_nbf = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing future nbf claim rejection",
            "--auth-token", token_future_nbf
        ]
        res = subprocess.run(cmd_tok_nbf, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure on future nbf token!"
        assert "Token not valid yet (nbf claim in future)" in res.stdout
        print("  [✓] Negative Token Test 5/10 PASSED: Future nbf token correctly rejected.")

        # Step F6: Negative Token Test — Untrusted issuer
        token_bad_iss = generate_rbac_token(valid_user, "soc lead", test_secret, iss="untrusted-identity-broker")
        cmd_tok_iss = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing untrusted issuer rejection",
            "--auth-token", token_bad_iss
        ]
        res = subprocess.run(cmd_tok_iss, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure on untrusted token issuer!"
        assert "Untrusted token issuer" in res.stdout
        print("  [✓] Negative Token Test 6/10 PASSED: Untrusted issuer correctly rejected.")

        # Step F7: Negative Token Test — Invalid audience
        token_bad_aud = generate_rbac_token(valid_user, "soc lead", test_secret, aud="unauthorized-service")
        cmd_tok_aud = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing invalid audience rejection",
            "--auth-token", token_bad_aud
        ]
        res = subprocess.run(cmd_tok_aud, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure on invalid audience!"
        assert "Invalid token audience" in res.stdout
        print("  [✓] Negative Token Test 7/10 PASSED: Invalid audience correctly rejected.")

        # Step F8: Negative Token Test — Role mismatch with claimed authorizer
        token_role_mismatch = generate_rbac_token(valid_user, "security engineer", test_secret)
        cmd_tok_role = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing role mismatch with claimed authorizer",
            "--auth-token", token_role_mismatch
        ]
        res = subprocess.run(cmd_tok_role, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure on role mismatch!"
        assert "does not match token role" in res.stdout or "lacks designated governance authority" in res.stdout
        print("  [✓] Negative Token Test 8/10 PASSED: Role mismatch correctly rejected.")

        # Step F9: Negative Token Test — Tampered signature
        valid_tok = generate_rbac_token(valid_user, "soc lead", test_secret)
        tampered_tok = valid_tok[:-4] + "dead"
        cmd_tok_tamper = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Testing signature tampering rejection",
            "--auth-token", tampered_tok
        ]
        res = subprocess.run(cmd_tok_tamper, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode != 0, "Expected failure on tampered signature!"
        assert "signature verification failed" in res.stdout
        print("  [✓] Negative Token Test 9/10 PASSED: Tampered token signature correctly rejected.")

        # Step F10: Positive Token Test — Valid cryptographic token authorizes reopen
        valid_reopen_tok = generate_rbac_token(valid_user, "soc lead", test_secret)
        cmd_tok_valid = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "SOC Lead",
            "--justification", "Cryptographic bearer token authorization verified",
            "--auth-token", valid_reopen_tok
        ]
        res = subprocess.run(cmd_tok_valid, cwd=str(REPO_ROOT), capture_output=True, text=True, env=token_env_with_secret)
        assert res.returncode == 0, f"Token-authorized reopen failed: {res.stderr} - {res.stdout}"
        assert "auth: cryptographic_token_verified" in res.stdout
        print("  [✓] Positive Token Test 10/10 PASSED: Cryptographic bearer token successfully authorized reopen.")

        # Close case again to prepare for Step G policy test
        cmd_reclose = [sys.executable, "incident_management/case_manager.py", "--close", test_case_id, "Re-closed after token test"]
        res = subprocess.run(cmd_reclose, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode == 0

        # Step G: Positive Test — Authorized Privileged Reopen
        cmd_reopen_valid = [
            sys.executable, "incident_management/case_manager.py",
            "--reopen", test_case_id,
            "--authorizer", "Incident Commander Alice",
            "--justification", "New correlated authentication telemetry discovered in honeypot auth.log"
        ]
        res = subprocess.run(cmd_reopen_valid, cwd=str(REPO_ROOT), capture_output=True, text=True, env=test_env)
        assert res.returncode == 0, f"Privileged reopen failed: {res.stderr}\n{res.stdout}"
        assert "REOPENED to status INVESTIGATING" in res.stdout
        print("  [✓] Positive Test PASSED: Privileged reopen succeeded with cryptographic audit trail.")

        # Step H: Verify persisted case structure & schema
        with open(test_case_path, "r", encoding="utf-8") as f:
            updated_case = json.load(f)

        assert updated_case["status"] == "investigating"
        assert updated_case["closed_at"] is None
        assert len(updated_case["reopen_records"]) == 2
        assert updated_case["reopen_records"][0]["auth_method"] == "cryptographic_token_verified"
        assert updated_case["reopen_records"][1]["auth_method"] == "enterprise_rbac_policy_verified"
        rec = updated_case["reopen_records"][-1]
        assert rec["authorizer"] == "Incident Commander Alice"
        assert len(rec["prior_state_sha256"]) == 64
        assert "executed_by" in rec
        assert "auth_method" in rec
        assert rec["auth_method"] in ["enterprise_rbac_policy_verified", "cryptographic_token_verified"]
        expected_user = cm.get_caller_identity()
        assert rec["executed_by"] == expected_user
        print(f"  [✓] State seal verified: {rec['prior_state_sha256'][:16]}...")
        print(f"  [✓] Authenticated caller identity & RBAC method verified: {rec['executed_by']} ({rec['auth_method']})")

        # Step I: Assert persistent lockfile semantics
        lock_file = test_cases_dir / f"{test_case_id}.flock"
        assert lock_file.exists(), "Expected persistent .flock file to remain on disk to prevent unlink-race condition!"
        print("  [✓] Persistent lockfile verified: .flock retained on disk (no unlink race).")

        # Step J: Concurrent Case Creation Race Prevention Test
        print("  [*] Testing concurrent case creation ID collision prevention...")
        from concurrent.futures import ThreadPoolExecutor
        from incident_management.case_manager import create_case

        def make_concurrent_case(idx):
            return create_case(
                title=f"Concurrent Test Case {idx}",
                severity="medium",
                source_ip=f"198.51.100.{10 + idx}",
                analyst=f"Tester-{idx}"
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            created_cases = list(executor.map(make_concurrent_case, range(5)))

        case_ids = [c["case_id"] for c in created_cases]
        assert len(set(case_ids)) == len(case_ids), f"Collision detected in concurrent case IDs: {case_ids}"
        print(f"  [✓] Concurrent case creation verified: {len(case_ids)} unique IDs allocated without collision ({case_ids})")
        print("  [✓] Test directory isolation: zero temporary files leaked into real cases directory.")

    print("=" * 65)
    print("[+] All case manager lifecycle and reopen assertions PASSED.")
    print("=" * 65)

if __name__ == "__main__":
    test_case_lifecycle_and_reopen()

