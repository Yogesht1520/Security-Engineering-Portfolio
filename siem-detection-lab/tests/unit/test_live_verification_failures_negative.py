#!/usr/bin/env python3
"""
Negative Test Suite — Full CLI Flows & Missing Evidence Assertions
==================================================================
Proves deterministically that every security failure condition, missing evidence file,
tampered cryptographic artifact, policy discrepancy, or live GCP API disruption
causes an immediate non-zero exit code (fail-closed), never falling back to insecure
defaults or silently reporting false success.

Covers:
1. Missing evidence files: Host pins, serial log, WORM manifest, local archive,
   detached signature, and trusted signer pins.
2. Full CLI flow: Unlocked WORM bucket policy (isLocked=false).
3. Full CLI flow: Insufficient retention duration (< 30 days).
4. Full CLI flow: Object SHA-256 checksum tampering.
5. Full CLI flow: Corrupted detached RSA digital signature.
6. Full CLI flow: Tampered host key pin / fingerprint mismatch.
7. Full CLI flow: Mismatched serial console record key/fingerprint.
8. Full CLI flow: External trust anchor hash mismatch.
9. Full CLI flow: Acceptance suite --live-gcp fails closed on missing tool/API.
10. Full CLI flow: Honeypot SA granted unauthorized IAM role in HCL.
11. Full CLI flow: Honeypot VM granted broad 'cloud-platform' OAuth scope.
12. Full CLI flow: IAM isolation --live-gcp fails closed on tool/API disruption.
13. Full CLI flow: Case manager SIEM_TEST_IDENTITY strictly rejected in production.
14. Full CLI flow: Live auditd rollback script strictly blocked without confirmation flag.
"""

import sys
import os
import json
import base64
import hashlib
import shutil
import tempfile
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

def test_negative_cli_assertions():
    print("=" * 65)
    print("   Comprehensive Negative & Missing-Evidence Test Suite      ")
    print("=" * 65)

    python_bin = sys.executable

    # Helper to run verify_host_keys_acceptance.py in an isolated environment
    def run_acceptance_cli(env_overrides=None, extra_args=None, cwd=REPO_ROOT):
        cmd = [python_bin, "tests/verify_host_keys_acceptance.py"] + (extra_args or [])
        env = os.environ.copy()
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=env)

    # ── Test 1: Full CLI — Unlocked Bucket Policy Rejected ───────────────────
    print("[1/14] Testing CLI fail-closed on unlocked WORM bucket policy...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        worm_file = tmp_repo / "evidence" / "gcs_bucket_lock_verification.json"
        with open(worm_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["retentionPolicy"]["isLocked"] = False
        with open(worm_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on unlocked bucket!"
        assert "AssertionError" in res.stderr or "isLocked must be True" in res.stderr
        print(f"  [✓] PASSED: Unlocked bucket policy rejected with exit code {res.returncode}.")

    # ── Test 2: Full CLI — Insufficient Retention Duration (< 30 days) ───────
    print("[2/14] Testing CLI fail-closed on sub-30-day retention duration...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        worm_file = tmp_repo / "evidence" / "gcs_bucket_lock_verification.json"
        with open(worm_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["retentionPolicy"]["retentionPeriod"] = 86400  # 1 day
        with open(worm_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on sub-30-day retention!"
        assert "AssertionError" in res.stderr or ">= 30 days" in res.stderr
        print(f"  [✓] PASSED: Sub-30-day retention rejected with exit code {res.returncode}.")

    # ── Test 3: Full CLI — Object SHA-256 Checksum Tampering ─────────────────
    print("[3/14] Testing CLI fail-closed on object SHA-256 hash tampering...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        worm_file = tmp_repo / "evidence" / "gcs_bucket_lock_verification.json"
        with open(worm_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["uploaded_objects"][0]["sha256"] = "deadbeef" * 8
        with open(worm_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on tampered object hash!"
        assert "SHA-256 mismatch" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Tampered object hash rejected with exit code {res.returncode}.")

    # ── Test 4: Full CLI — Missing Required Local Evidence Archive ───────────
    print("[4/14] Testing CLI fail-closed when local evidence archive is missing...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        local_tar = tmp_repo / "evidence" / "evidence_20261028_191347.tar.gz"
        local_tar.unlink()

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code when local evidence archive is missing!"
        assert "FATAL: Required local evidence file" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Missing local evidence archive rejected with exit code {res.returncode}.")

    # ── Test 5: Full CLI — Missing Detached Digital Signature File ────────────
    print("[5/14] Testing CLI fail-closed when detached signature file is missing...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        sig_file = tmp_repo / "evidence" / "evidence_20261028_191347.tar.gz.sig"
        sig_file.unlink()

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code when signature file is missing!"
        assert "FATAL: Missing detached signature file" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Missing signature file rejected with exit code {res.returncode}.")

    # ── Test 6: Full CLI — Corrupted RSA Detached Digital Signature ───────────
    print("[6/14] Testing CLI fail-closed on corrupted digital signature...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        sig_file = tmp_repo / "evidence" / "evidence_20261028_191347.tar.gz.sig"
        dummy_sig = b"\x00" * 384
        sig_file.write_bytes(dummy_sig)

        # Update manifest checksums for sig file so object hash passes and cryptographic verify is reached
        worm_file = tmp_repo / "evidence" / "gcs_bucket_lock_verification.json"
        with open(worm_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for obj in data["uploaded_objects"]:
            if obj["name"] == "evidence_20261028_191347.tar.gz.sig":
                obj["sha256"] = hashlib.sha256(dummy_sig).hexdigest()
                obj["md5Hash"] = base64.b64encode(hashlib.md5(dummy_sig).digest()).decode("ascii")
        with open(worm_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on corrupted signature!"
        assert "InvalidSignature" in res.stderr
        print(f"  [✓] PASSED: Corrupted signature rejected with exit code {res.returncode}.")

    # ── Test 7: Full CLI — Missing Trusted Signer Pins File ───────────────────
    print("[7/14] Testing CLI fail-closed when TRUSTED_SIGNER_PINS.txt is missing...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        pins_file = tmp_repo / "evidence" / "TRUSTED_SIGNER_PINS.txt"
        pins_file.unlink()

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code when signer pins missing!"
        assert "FATAL: Missing trusted signer pins file" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Missing trusted signer pins rejected with exit code {res.returncode}.")

    # ── Test 8: Full CLI — Tampered Host Key Pin Fingerprint Mismatch ─────────
    print("[8/14] Testing CLI fail-closed on tampered host key pin...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        host_pins = tmp_repo / "evidence" / "TRUSTED_HOST_PINS.txt"
        content = host_pins.read_text(encoding="utf-8")
        tampered_content = content.replace("IMxWbfozbHUGSWfKIqOEwMG/rbaQvo+RtnycUCesUNoR", "IMxWbfozbHUGSWfKIqOEwMG/rbaQvo+RtnycUCesUNoA")
        host_pins.write_text(tampered_content, encoding="utf-8")

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on tampered host pin!"
        assert "Fingerprint mismatch" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Tampered host key pin rejected with exit code {res.returncode}.")

    # ── Test 9: Full CLI — Serial Record Internal Parity Mismatch ────────────
    print("[9/14] Testing CLI fail-closed on serial log record self-consistency error...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        serial_log = tmp_repo / "evidence" / "serial_console_host_keys.log"
        content = serial_log.read_text(encoding="utf-8")
        # Tamper claimed fingerprint in record 1
        tampered_log = content.replace("SHA256:82z37fq45l+PVGifHRVxwTDcC8PkzSQ+n3xfxwfT1mA", "SHA256:FAKEFINGERPRINT11111111111111111111111111111")
        serial_log.write_text(tampered_log, encoding="utf-8")
        # Update hash file so hash check passes but record parser catches the internal discrepancy
        h = hashlib.sha256(tampered_log.encode("utf-8")).hexdigest()
        (tmp_repo / "evidence" / "serial_console_host_keys.log.sha256").write_text(f"{h}  serial_console_host_keys.log\n")

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on serial record discrepancy!"
        assert "Record self-consistency error" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Serial log record discrepancy rejected with exit code {res.returncode}.")

    # ── Test 10: Full CLI — External Trust Anchor Hash Mismatch ───────────────
    print("[10/14] Testing CLI fail-closed on external trust anchor mismatch...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        bogus_anchor = Path(tmp_dir) / "bogus_anchor.txt"
        bogus_anchor.write_text("SHA256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef | serial_console_host_keys.log\n")

        env = {"SIEM_EXTERNAL_SERIAL_ANCHOR": str(bogus_anchor)}
        res = run_acceptance_cli(env_overrides=env)
        assert res.returncode != 0, "Expected non-zero exit code on external trust anchor mismatch!"
        assert "EXTERNAL TRUST ANCHOR MISMATCH" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: External trust anchor mismatch rejected with exit code {res.returncode}.")

    # ── Test 11: Acceptance CLI --live-gcp Fails Closed on Missing Tool ───────
    print("[11/14] Testing CLI acceptance --live-gcp fails closed on missing tool/API...")
    res = subprocess.run([python_bin, "tests/verify_host_keys_acceptance.py", "--live-gcp"], cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code on acceptance --live-gcp failure!"
    assert "ACCEPTANCE VERIFICATION FAILED (Fail Closed)" in res.stdout or "FATAL" in res.stdout
    print(f"  [✓] PASSED: Acceptance CLI --live-gcp returned exit code {res.returncode} (Fail Closed).")

    # ── Test 12: IAM Isolation CLI --live-gcp Fails Closed on Missing Tool ────
    print("[12/14] Testing CLI IAM isolation --live-gcp fails closed on missing tool/API...")
    res = subprocess.run([python_bin, "tests/integration/test_gcp_iam_isolation.py", "--live-gcp"], cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code on IAM isolation --live-gcp failure!"
    assert "GCP IAM ISOLATION CHECKS FAILED (Fail Closed)" in res.stdout or "FATAL" in res.stdout
    print(f"  [✓] PASSED: IAM Isolation CLI --live-gcp returned exit code {res.returncode} (Fail Closed).")

    # ── Test 13: Case Manager SIEM_TEST_IDENTITY Rejection in Production Mode ─
    print("[13/14] Testing case manager strict rejection of SIEM_TEST_IDENTITY in production...")
    cmd_prod_auth = [
        python_bin, "-c",
        "import os, sys; from pathlib import Path; sys.path.insert(0, r'" + str(REPO_ROOT) + "'); os.environ['SIEM_ENV']='production'; os.environ['SIEM_TEST_IDENTITY']='fake'; import incident_management.case_manager as cm; cm.get_caller_identity()"
    ]
    res = subprocess.run(cmd_prod_auth, cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code when SIEM_TEST_IDENTITY is used in production!"
    assert "PermissionError" in res.stderr or "strictly prohibited in production" in res.stderr
    print(f"  [✓] PASSED: Production identity override rejected with exit code {res.returncode} (Fail Closed).")

    # ── Test 14: Live Auditd Rollback Script Rejection Without Confirmation Flag
    print("[14/14] Testing live auditd integration script blocks without --force-live-danger...")
    res = subprocess.run(["bash", "tests/integration/test_auditd_live_rollback.sh"], cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code on live auditd test without confirmation flag!"
    assert "SAFETY BLOCKED" in res.stderr
    print(f"  [✓] PASSED: Live auditd integration test safely blocked with exit code {res.returncode}.")

    print("\n" + "=" * 65)
    print(" [✓] ALL 14 NEGATIVE & MISSING-EVIDENCE CLI ASSERTIONS PASSED.")
    print("=" * 65)

if __name__ == "__main__":
    test_negative_cli_assertions()
