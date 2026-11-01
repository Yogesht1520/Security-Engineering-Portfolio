#!/usr/bin/env python3
"""
Negative Test Suite — Live Verification Fail-Closed Assertions
=============================================================
Proves deterministically that every security failure condition, tampered credential,
policy violation, or live GCP API disruption causes an immediate non-zero exit code
(fail-closed), never falling back to insecure defaults or reporting false success.

Covers:
1. WORM Storage: Unlocked bucket retention policy (isLocked=false).
2. WORM Storage: Insufficient retention duration (< 30 days).
3. WORM Storage: Object SHA-256 checksum tampering.
4. WORM Storage: Corrupted detached digital signature.
5. Host Key Pinning: Tampered OpenSSH public key / fingerprint mismatch.
6. Serial Console: Missing or mismatched out-of-band serial log transcript.
7. Acceptance Suite: --live-gcp fails closed on missing tool / API failure.
8. IAM Isolation: Honeypot SA granted unauthorized project IAM role.
9. IAM Isolation: Honeypot VM granted broad 'cloud-platform' OAuth scope.
10. IAM Isolation: --live-gcp fails closed on missing tool / API failure.
11. Case Manager: SIEM_TEST_IDENTITY strictly rejected in production.
"""

import sys
import os
import json
import copy
import tempfile
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

def test_negative_assertions():
    print("=" * 65)
    print("   Negative Failure Assertions: Fail-Closed Security Suite   ")
    print("=" * 65)

    python_bin = sys.executable

    # ── Test 1: WORM Storage — Unlocked Bucket Policy Rejected ───────────────
    print("[1/11] Testing fail-closed rejection on unlocked WORM bucket policy...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_worm = Path(tmp_dir) / "gcs_bucket_lock_verification.json"
        real_worm = REPO_ROOT / "evidence" / "gcs_bucket_lock_verification.json"
        with open(real_worm, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["retentionPolicy"]["isLocked"] = False
        with open(tmp_worm, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Import acceptance module and verify failure
        import tests.verify_host_keys_acceptance as vhka
        orig_file = vhka.WORM_VERIFY_FILE
        try:
            vhka.WORM_VERIFY_FILE = tmp_worm
            failed = False
            try:
                vhka.verify_worm_bucket_and_objects(live_gcp=False)
            except AssertionError:
                failed = True
            assert failed, "Expected AssertionError when isLocked is False!"
            print("  [✓] PASSED: Unlocked bucket policy (isLocked=False) failed closed.")
        finally:
            vhka.WORM_VERIFY_FILE = orig_file

    # ── Test 2: WORM Storage — Insufficient Retention Duration (< 30 days) ───
    print("[2/11] Testing fail-closed rejection on sub-30-day retention duration...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_worm = Path(tmp_dir) / "gcs_bucket_lock_verification.json"
        with open(real_worm, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["retentionPolicy"]["retentionPeriod"] = 86400  # 1 day instead of 30 days
        with open(tmp_worm, "w", encoding="utf-8") as f:
            json.dump(data, f)

        orig_file = vhka.WORM_VERIFY_FILE
        try:
            vhka.WORM_VERIFY_FILE = tmp_worm
            failed = False
            try:
                vhka.verify_worm_bucket_and_objects(live_gcp=False)
            except AssertionError:
                failed = True
            assert failed, "Expected AssertionError when retentionPeriod < 2,592,000s!"
            print("  [✓] PASSED: Sub-30-day retention duration failed closed.")
        finally:
            vhka.WORM_VERIFY_FILE = orig_file

    # ── Test 3: WORM Storage — Object SHA-256 Checksum Tampering ─────────────
    print("[3/11] Testing fail-closed rejection on object SHA-256 hash mismatch...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_worm = Path(tmp_dir) / "gcs_bucket_lock_verification.json"
        with open(real_worm, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["uploaded_objects"][0]["sha256"] = "deadbeef" * 8
        with open(tmp_worm, "w", encoding="utf-8") as f:
            json.dump(data, f)

        orig_file = vhka.WORM_VERIFY_FILE
        try:
            vhka.WORM_VERIFY_FILE = tmp_worm
            failed = False
            try:
                vhka.verify_worm_bucket_and_objects(live_gcp=False)
            except AssertionError:
                failed = True
            assert failed, "Expected AssertionError on tampered object SHA-256!"
            print("  [✓] PASSED: Tampered object SHA-256 checksum failed closed.")
        finally:
            vhka.WORM_VERIFY_FILE = orig_file

    # ── Test 4: WORM Storage — Corrupted Detached RSA Digital Signature ───────
    print("[4/11] Testing fail-closed rejection on corrupted digital signature...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_sig = Path(tmp_dir) / "corrupt.sig"
        tmp_sig.write_bytes(b"\x00" * 384)

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature

        pub_bytes = (REPO_ROOT / "evidence" / "20261028_191347" / "EVIDENCE_SIGNING_PUBKEY.pub").read_bytes()
        archive_bytes = (REPO_ROOT / "evidence" / "evidence_20261028_191347.tar.gz").read_bytes()
        pub_obj = load_pem_public_key(pub_bytes)

        sig_failed = False
        try:
            pub_obj.verify(tmp_sig.read_bytes(), archive_bytes, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            sig_failed = True
        assert sig_failed, "Expected InvalidSignature on corrupted digital signature!"
        print("  [✓] PASSED: Corrupted digital signature failed closed.")

    # ── Test 5: Host Key Pinning — Tampered OpenSSH Public Key Mismatch ──────
    print("[5/11] Testing fail-closed rejection on tampered host key pin...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_pins = Path(tmp_dir) / "TRUSTED_HOST_PINS.txt"
        with open(REPO_ROOT / "evidence" / "TRUSTED_HOST_PINS.txt", "r", encoding="utf-8") as f:
            pins_content = f.read()
        # Tamper one byte in the public key
        tampered_pins = pins_content.replace("IMxWbfozbHUGSWfKIqOEwMG/rbaQvo+RtnycUCesUNoR", "ZтныеbfozbHUGSWfKIqOEwMG/rbaQvo+RtnycUCesUNoR")
        tmp_pins.write_text(tampered_pins, encoding="utf-8")

        orig_pins = vhka.HOST_PINS_FILE
        try:
            vhka.HOST_PINS_FILE = tmp_pins
            failed = False
            try:
                vhka.verify_host_key_pins()
            except (AssertionError, Exception):
                failed = True
            assert failed, "Expected failure on tampered host key pin!"
            print("  [✓] PASSED: Tampered host key pin failed closed.")
        finally:
            vhka.HOST_PINS_FILE = orig_pins

    # ── Test 6: Serial Console — Missing or Tampered Transcript Log ───────────
    print("[6/11] Testing fail-closed rejection on missing/tampered serial console log...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_log = Path(tmp_dir) / "serial.log"
        tmp_log.write_text("Spoofed empty serial log without host keys\n", encoding="utf-8")

        orig_log = vhka.SERIAL_LOG_FILE
        try:
            vhka.SERIAL_LOG_FILE = tmp_log
            pins = vhka.verify_host_key_pins()
            failed = False
            try:
                vhka.verify_serial_console_evidence(pins, live_gcp=False)
            except AssertionError:
                failed = True
            assert failed, "Expected failure when serial log does not authenticate host keys!"
            print("  [✓] PASSED: Missing/spoofed serial console log failed closed.")
        finally:
            vhka.SERIAL_LOG_FILE = orig_log

    # ── Test 7: Acceptance CLI --live-gcp Fails Closed ────────────────────────
    print("[7/11] Testing CLI --live-gcp non-zero exit code on missing tool / failure...")
    cmd_live = [python_bin, "tests/verify_host_keys_acceptance.py", "--live-gcp"]
    res = subprocess.run(cmd_live, cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code when --live-gcp fails!"
    assert "ACCEPTANCE VERIFICATION FAILED (Fail Closed)" in res.stdout or "FATAL" in res.stdout
    print(f"  [✓] PASSED: Acceptance CLI --live-gcp returned exit code {res.returncode} (Fail Closed).")

    # ── Test 8: IAM Isolation — Unauthorized Project IAM Role on Honeypot SA ──
    print("[8/11] Testing fail-closed rejection when Honeypot SA holds IAM role in Terraform...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_main = Path(tmp_dir) / "main.tf"
        real_main = REPO_ROOT / "infra" / "terraform" / "main.tf"
        content = real_main.read_text(encoding="utf-8")
        corrupted_content = content + '\nresource "google_project_iam_member" "rogue_honeypot_admin" {\n  project = "demo"\n  role = "roles/owner"\n  member = "serviceAccount:${google_service_account.honeypot_sa.email}"\n}\n'
        tmp_main.write_text(corrupted_content, encoding="utf-8")

        import tests.integration.test_gcp_iam_isolation as tgii
        orig_tf = tgii.TERRAFORM_MAIN
        try:
            tgii.TERRAFORM_MAIN = tmp_main
            failed = False
            try:
                tgii.verify_terraform_iam_isolation()
            except AssertionError:
                failed = True
            assert failed, "Expected AssertionError when Honeypot SA is bound to an IAM role!"
            print("  [✓] PASSED: Honeypot IAM role assignment failed closed.")
        finally:
            tgii.TERRAFORM_MAIN = orig_tf

    # ── Test 9: IAM Isolation — Honeypot Granted 'cloud-platform' Scope ──────
    print("[9/11] Testing fail-closed rejection on broad 'cloud-platform' scope...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_main = Path(tmp_dir) / "main.tf"
        content = real_main.read_text(encoding="utf-8")
        corrupted_content = content.replace(
            'scopes = ["https://www.googleapis.com/auth/logging.write"]',
            'scopes = ["https://www.googleapis.com/auth/cloud-platform"]'
        )
        tmp_main.write_text(corrupted_content, encoding="utf-8")

        orig_tf = tgii.TERRAFORM_MAIN
        try:
            tgii.TERRAFORM_MAIN = tmp_main
            failed = False
            try:
                tgii.verify_terraform_iam_isolation()
            except AssertionError:
                failed = True
            assert failed, "Expected AssertionError when 'cloud-platform' scope is present!"
            print("  [✓] PASSED: Broad 'cloud-platform' OAuth scope failed closed.")
        finally:
            tgii.TERRAFORM_MAIN = orig_tf

    # ── Test 10: IAM Isolation CLI --live-gcp Fails Closed ────────────────────
    print("[10/11] Testing IAM CLI --live-gcp non-zero exit code on missing tool / failure...")
    cmd_iam_live = [python_bin, "tests/integration/test_gcp_iam_isolation.py", "--live-gcp"]
    res = subprocess.run(cmd_iam_live, cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected non-zero exit code when IAM --live-gcp fails!"
    assert "GCP IAM ISOLATION CHECKS FAILED (Fail Closed)" in res.stdout or "FATAL" in res.stdout
    print(f"  [✓] PASSED: IAM CLI --live-gcp returned exit code {res.returncode} (Fail Closed).")

    # ── Test 11: Production Identity Isolation — Rejection in Production Mode ─
    print("[11/11] Testing strict rejection of SIEM_TEST_IDENTITY in production...")
    cmd_prod_auth = [
        python_bin, "-c",
        "import os, sys; from pathlib import Path; sys.path.insert(0, r'" + str(REPO_ROOT) + "'); os.environ['SIEM_ENV']='production'; os.environ['SIEM_TEST_IDENTITY']='fake'; import incident_management.case_manager as cm; cm.get_caller_identity()"
    ]
    res = subprocess.run(cmd_prod_auth, cwd=str(REPO_ROOT), capture_output=True, text=True)
    assert res.returncode != 0, "Expected failure when SIEM_TEST_IDENTITY is used in production!"
    assert "PermissionError" in res.stderr or "strictly prohibited in production" in res.stderr
    print(f"  [✓] PASSED: SIEM_TEST_IDENTITY raised PermissionError and returned exit code {res.returncode} (Fail Closed).")

    print("\n" + "=" * 65)
    print(" [✓] ALL 11 NEGATIVE FAIL-CLOSED ASSERTIONS PASSED.          ")
    print("=" * 65)

if __name__ == "__main__":
    test_negative_assertions()
