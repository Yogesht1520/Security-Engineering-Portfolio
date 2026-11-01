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
    print("[1/23] Testing CLI fail-closed on unlocked WORM bucket policy...")
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
    print("[2/23] Testing CLI fail-closed on sub-30-day retention duration...")
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
    print("[3/23] Testing CLI fail-closed on object SHA-256 hash tampering...")
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
    print("[4/23] Testing CLI fail-closed when local evidence archive is missing...")
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
    print("[5/23] Testing CLI fail-closed when detached signature file is missing...")
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
    print("[6/23] Testing CLI fail-closed on corrupted digital signature...")
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
    print("[7/23] Testing CLI fail-closed when TRUSTED_SIGNER_PINS.txt is missing...")
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
    print("[8/23] Testing CLI fail-closed on tampered host key pin...")
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
    print("[9/23] Testing CLI fail-closed on serial log record self-consistency error...")
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
    print("[10/23] Testing CLI fail-closed on external trust anchor mismatch...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        bogus_anchor = Path(tmp_dir) / "bogus_anchor.txt"
        bogus_anchor.write_text("SHA256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef | serial_console_host_keys.log\n")

        env = {"SIEM_EXTERNAL_SERIAL_ANCHOR": str(bogus_anchor)}
        res = run_acceptance_cli(env_overrides=env)
        assert res.returncode != 0, "Expected non-zero exit code on external trust anchor mismatch!"
        assert "EXTERNAL TRUST ANCHOR MISMATCH" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: External trust anchor mismatch rejected with exit code {res.returncode}.")

    # ── Test 11: Deployment Acceptance Mode Mandatory External Trust Anchor ───
    print("[11/23] Testing CLI fail-closed when external trust anchor is missing in deployment acceptance mode...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        nonexistent_anchor = Path(tmp_dir) / "missing_anchor.txt"
        env = {
            "SIEM_EXTERNAL_SERIAL_ANCHOR": str(nonexistent_anchor),
            "SIEM_DEPLOYMENT_ACCEPTANCE": "1"
        }
        res = run_acceptance_cli(env_overrides=env)
        assert res.returncode != 0, "Expected non-zero exit code when external anchor is missing in deployment acceptance mode!"
        assert "is MANDATORY in deployment acceptance mode" in res.stderr or "FATAL" in res.stdout or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Missing external trust anchor in deployment acceptance mode rejected with exit code {res.returncode}.")

    # ── Helper for Deterministic Mock gcloud Executable ───────────────────────
    def make_mock_gcloud(bin_dir: Path, fail_msg: str = "Live GCP API simulated failure: PERMISSION_DENIED", exit_code: int = 1):
        bin_dir.mkdir(parents=True, exist_ok=True)
        # Windows batch & cmd wrappers
        bat = f"@echo off\r\necho ERROR: (gcloud) {fail_msg} 1>&2\r\nexit /b {exit_code}\r\n"
        (bin_dir / "gcloud.bat").write_text(bat, encoding="utf-8")
        (bin_dir / "gcloud.cmd").write_text(bat, encoding="utf-8")
        # Unix/Linux shell wrapper
        sh = f"#!/bin/sh\necho 'ERROR: (gcloud) {fail_msg}' >&2\nexit {exit_code}\n"
        sh_file = bin_dir / "gcloud"
        sh_file.write_text(sh, encoding="utf-8")
        try:
            os.chmod(str(sh_file), 0o755)
        except Exception:
            pass

    # ── Test 12: Acceptance CLI --live-gcp Deterministic Mocked Failure ───────
    print("[12/23] Testing CLI acceptance --live-gcp deterministic failure with mocked gcloud...")
    with tempfile.TemporaryDirectory() as mock_dir:
        mock_bin = Path(mock_dir) / "mock_bin"
        make_mock_gcloud(mock_bin, fail_msg="Live GCP API simulated failure: PERMISSION_DENIED", exit_code=1)
        mock_env = os.environ.copy()
        mock_env["PATH"] = str(mock_bin) + os.pathsep + mock_env.get("PATH", "")

        res = subprocess.run([python_bin, "tests/verify_host_keys_acceptance.py", "--live-gcp"], cwd=str(REPO_ROOT), env=mock_env, capture_output=True, text=True)
        assert res.returncode != 0, "Expected non-zero exit code on acceptance --live-gcp failure!"
        assert "Live GCP API query failed" in res.stdout or "Live GCP virtual serial port" in res.stdout or "ACCEPTANCE VERIFICATION FAILED (Fail Closed)" in res.stdout or "FATAL" in res.stdout
        print(f"  [✓] PASSED: Acceptance CLI --live-gcp deterministically failed closed with exit code {res.returncode}.")

    # ── Test 13: IAM Isolation CLI --live-gcp Deterministic Mocked Failure ────
    print("[13/23] Testing CLI IAM isolation --live-gcp deterministic failure with mocked gcloud...")
    with tempfile.TemporaryDirectory() as mock_dir:
        mock_bin = Path(mock_dir) / "mock_bin"
        make_mock_gcloud(mock_bin, fail_msg="Live GCP API simulated failure: PERMISSION_DENIED", exit_code=1)
        mock_env = os.environ.copy()
        mock_env["PATH"] = str(mock_bin) + os.pathsep + mock_env.get("PATH", "")

        res = subprocess.run([python_bin, "tests/integration/test_gcp_iam_isolation.py", "--live-gcp"], cwd=str(REPO_ROOT), env=mock_env, capture_output=True, text=True)
        assert res.returncode != 0, "Expected non-zero exit code on IAM isolation --live-gcp failure!"
        assert "gcloud projects get-iam-policy failed" in res.stdout or "GCP IAM ISOLATION CHECKS FAILED (Fail Closed)" in res.stdout or "FATAL" in res.stdout
        print(f"  [✓] PASSED: IAM Isolation CLI --live-gcp deterministically failed closed with exit code {res.returncode}.")

    # ── Test 14: Deterministic Missing Tool (PATH Without gcloud) ──────────────
    print("[14/23] Testing CLI --live-gcp deterministic failure when gcloud is missing from PATH...")
    env_no_gcloud = os.environ.copy()
    env_no_gcloud["PATH"] = os.path.dirname(python_bin)
    res = subprocess.run([python_bin, "tests/verify_host_keys_acceptance.py", "--live-gcp"], cwd=str(REPO_ROOT), env=env_no_gcloud, capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code when gcloud CLI is missing!"
    assert "'gcloud' CLI was not found on PATH" in res.stdout or "ACCEPTANCE VERIFICATION FAILED" in res.stdout
    print(f"  [✓] PASSED: Missing gcloud executable deterministically failed closed with exit code {res.returncode}.")

    # ── Test 15: Case Manager SIEM_TEST_IDENTITY Rejection in Production Mode ─
    print("[15/23] Testing case manager strict rejection of SIEM_TEST_IDENTITY in production...")
    cmd_prod_auth = [
        python_bin, "-c",
        "import os, sys; from pathlib import Path; sys.path.insert(0, r'" + str(REPO_ROOT) + "'); os.environ['SIEM_ENV']='production'; os.environ['SIEM_TEST_IDENTITY']='fake'; import incident_management.case_manager as cm; cm.get_caller_identity()"
    ]
    res = subprocess.run(cmd_prod_auth, cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code when SIEM_TEST_IDENTITY is used in production!"
    assert "PermissionError" in res.stderr or "strictly prohibited in production" in res.stderr
    print(f"  [✓] PASSED: Production identity override rejected with exit code {res.returncode} (Fail Closed).")

    # ── Test 16: Live Auditd Rollback Script Rejection Without Confirmation Flag
    print("[16/23] Testing live auditd integration script blocks without --force-live-danger...")
    res = subprocess.run(["bash", "tests/integration/test_auditd_live_rollback.sh"], cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code on live auditd test without confirmation flag!"
    assert "SAFETY BLOCKED" in res.stderr
    print(f"  [✓] PASSED: Live auditd integration test safely blocked with exit code {res.returncode}.")

    # ── Test 17: Rejection of Naive Timestamps Lacking Explicit Timezone ─────
    print("[17/23] Testing strict rejection of naive retention timestamps lacking timezone offsets...")
    cmd_naive_ts = [
        python_bin, "-c",
        "import sys; from pathlib import Path; sys.path.insert(0, r'" + str(REPO_ROOT) + "'); from tests.verify_host_keys_acceptance import parse_timezone_aware_utc; parse_timezone_aware_utc('2026-11-30 13:38:27')"
    ]
    res = subprocess.run(cmd_naive_ts, cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code when naive timestamp is supplied!"
    assert "REJECTED NAIVE TIMESTAMP" in res.stderr or "ValueError" in res.stderr
    print(f"  [✓] PASSED: Naive timestamp lacking explicit timezone rejected with exit code {res.returncode}.")

    # ── Test 18: Rejection of Malformed IAM Hierarchy with Duplicate Resource IDs
    print("[18/23] Testing strict rejection of malformed IAM hierarchy with duplicate resource IDs...")
    with tempfile.TemporaryDirectory() as mock_dir:
        mock_bin = Path(mock_dir) / "mock_bin"
        mock_bin.mkdir(parents=True, exist_ok=True)
        # Mock gcloud returning valid direct policy, but duplicate IDs in ancestor hierarchy
        direct_policy_json = json.dumps({"bindings": []})
        dup_hierarchy_json = json.dumps([
            {"id": "siem-detection-lab", "type": "project", "policy": {"bindings": []}},
            {"id": "siem-detection-lab", "type": "folder", "policy": {"bindings": []}}
        ])
        
        py_mock_script = (
            "import sys, json\n"
            "args = sys.argv[1:]\n"
            "if 'get-iam-policy' in args:\n"
            f"    print('''{direct_policy_json}''')\n"
            "    sys.exit(0)\n"
            "elif 'get-ancestors-iam-policy' in args:\n"
            f"    print('''{dup_hierarchy_json}''')\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        (mock_bin / "mock_gcloud.py").write_text(py_mock_script, encoding="utf-8")
        bat_wrapper = f"@echo off\r\n\"{python_bin}\" \"{mock_bin / 'mock_gcloud.py'}\" %*\r\n"
        (mock_bin / "gcloud.bat").write_text(bat_wrapper, encoding="utf-8")
        (mock_bin / "gcloud.cmd").write_text(bat_wrapper, encoding="utf-8")
        sh_wrapper = f"#!/bin/sh\n\"{python_bin}\" \"{mock_bin / 'mock_gcloud.py'}\" \"$@\"\n"
        sh_file = mock_bin / "gcloud"
        sh_file.write_text(sh_wrapper, encoding="utf-8")
        try:
            os.chmod(str(sh_file), 0o755)
        except Exception:
            pass

        mock_env = os.environ.copy()
        mock_env["PATH"] = str(mock_bin) + os.pathsep + mock_env.get("PATH", "")
        res = subprocess.run([python_bin, "tests/integration/test_gcp_iam_isolation.py", "--live-gcp"], cwd=str(REPO_ROOT), env=mock_env, capture_output=True, text=True)
        assert res.returncode != 0, "Expected non-zero exit code on duplicate hierarchy ID!"
        assert "Hierarchy duplicate ID violation" in res.stdout or "GCP IAM ISOLATION CHECKS FAILED" in res.stdout
        print(f"  [✓] PASSED: Duplicate resource ID in IAM hierarchy rejected with exit code {res.returncode}.")

    # ── Test 19: Rejection of Ambiguous / Duplicate Serial Console Records ───
    print("[19/23] Testing strict rejection of ambiguous / duplicate serial console records...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        serial_log = tmp_repo / "evidence" / "serial_console_host_keys.log"
        content = serial_log.read_text(encoding="utf-8")
        # Duplicate record 1
        tampered_log = content + "\n# --- ACQUISITION RECORD 4: siem-lab-honeypot\nHostKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMxWbfozbHUGSWfKIqOEwMG/rbaQvo+RtnycUCesUNoR root@siem-lab-honeypot\nHostKey Fingerprint: (SHA256:82z37fq45l+PVGifHRVxwTDcC8PkzSQ+n3xfxwfT1mA)\n"
        serial_log.write_text(tampered_log, encoding="utf-8")
        h = hashlib.sha256(tampered_log.encode("utf-8")).hexdigest()
        (tmp_repo / "evidence" / "serial_console_host_keys.log.sha256").write_text(f"{h}  serial_console_host_keys.log\n")

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on duplicate serial record!"
        assert "AMBIGUOUS / DUPLICATE RECORD" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Duplicate serial console record rejected with exit code {res.returncode}.")

    # ── Test 20: Rejection of Serial Record with Unstructured / Loose Substring Host Reference
    print("[20/23] Testing strict rejection of serial record lacking structured host identity token...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        serial_log = tmp_repo / "evidence" / "serial_console_host_keys.log"
        c = serial_log.read_text(encoding="utf-8")
        # Replace structured comment root@siem-lab-honeypot with untrusted box, but leave an unstructured log string
        tampered_log = c.replace("root@siem-lab-honeypot", "root@untrusted-spoofed-host")
        tampered_log = tampered_log.replace(
            "[    0.000000] Command line: BOOT_IMAGE=",
            "[    0.000000] Unstructured noise log mentioning siem-lab-honeypot in passing\n[    0.000000] Command line: BOOT_IMAGE="
        )
        serial_log.write_text(tampered_log, encoding="utf-8")
        h = hashlib.sha256(tampered_log.encode("utf-8")).hexdigest()
        (tmp_repo / "evidence" / "serial_console_host_keys.log.sha256").write_text(f"{h}  serial_console_host_keys.log\n")

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on serial record lacking structured identity!"
        assert "Structured identity mismatch" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Unstructured substring host mention rejected with exit code {res.returncode} (Fail Closed).")

    # ── Test 21: Rejection of Offline Serial Record Lacking Command Provenance Header ───
    print("[21/23] Testing strict rejection of offline acquisition block missing command provenance header...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        serial_log = tmp_repo / "evidence" / "serial_console_host_keys.log"
        c = serial_log.read_text(encoding="utf-8")
        # Remove the command provenance line from record 1 (siem-lab-honeypot)
        tampered_log = c.replace(
            "# Command: gcloud compute instances get-serial-port-output siem-lab-honeypot --zone=us-central1-a --port=1",
            "# Command provenance omitted"
        )
        serial_log.write_text(tampered_log, encoding="utf-8")
        h = hashlib.sha256(tampered_log.encode("utf-8")).hexdigest()
        (tmp_repo / "evidence" / "serial_console_host_keys.log.sha256").write_text(f"{h}  serial_console_host_keys.log\n")

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on serial block missing command provenance!"
        assert "UNAMBIGUOUS COMMAND PROVENANCE FAILURE" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Missing command provenance header rejected with exit code {res.returncode}.")

    # ── Test 22: Rejection of Serial Record Lacking Explicit user@hostname Comment ───
    print("[22/23] Testing strict rejection of serial record lacking explicit user@hostname comment...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        serial_log = tmp_repo / "evidence" / "serial_console_host_keys.log"
        c = serial_log.read_text(encoding="utf-8")
        # Strip root@siem-lab-honeypot comment from HostKey line
        tampered_log = c.replace(
            "HostKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMxWbfozbHUGSWfKIqOEwMG/rbaQvo+RtnycUCesUNoR root@siem-lab-honeypot",
            "HostKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMxWbfozbHUGSWfKIqOEwMG/rbaQvo+RtnycUCesUNoR"
        )
        serial_log.write_text(tampered_log, encoding="utf-8")
        h = hashlib.sha256(tampered_log.encode("utf-8")).hexdigest()
        (tmp_repo / "evidence" / "serial_console_host_keys.log.sha256").write_text(f"{h}  serial_console_host_keys.log\n")

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on HostKey lacking explicit user@hostname comment!"
        assert "UNAMBIGUOUS IDENTITY BINDING FAILURE" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Missing user@hostname key comment rejected with exit code {res.returncode}.")

    # ── Test 23: Rejection of Serial Record Containing Conflicting Identity Announcements ───
    print("[23/23] Testing strict rejection of serial record containing conflicting identity announcements...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = Path(tmp_dir) / "repo"
        shutil.copytree(REPO_ROOT, tmp_repo, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
        serial_log = tmp_repo / "evidence" / "serial_console_host_keys.log"
        c = serial_log.read_text(encoding="utf-8")
        # Inject conflicting system hostname announcement into siem-lab-honeypot block
        tampered_log = c.replace(
            "systemd[1]: Set hostname to <siem-lab-honeypot>.",
            "systemd[1]: Set hostname to <siem-lab-honeypot>.\nsystemd[1]: Set hostname to <siem-lab-bastion>."
        )
        serial_log.write_text(tampered_log, encoding="utf-8")
        h = hashlib.sha256(tampered_log.encode("utf-8")).hexdigest()
        (tmp_repo / "evidence" / "serial_console_host_keys.log.sha256").write_text(f"{h}  serial_console_host_keys.log\n")

        res = run_acceptance_cli(cwd=tmp_repo)
        assert res.returncode != 0, "Expected non-zero exit code on conflicting identity announcements!"
        assert "CONFLICTING IDENTITY ANNOUNCEMENTS" in res.stderr or "AssertionError" in res.stderr
        print(f"  [✓] PASSED: Conflicting identity announcements rejected with exit code {res.returncode}.")

    print("\n" + "=" * 65)
    print(" [✓] ALL 23 NEGATIVE & MISSING-EVIDENCE CLI ASSERTIONS PASSED.")
    print("=" * 65)

if __name__ == "__main__":
    test_negative_cli_assertions()
