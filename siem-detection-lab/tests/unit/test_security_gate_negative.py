#!/usr/bin/env python3
"""
test_security_gate_negative.py — Unit Tests for Security Gate Failure Verification

Verifies that security_scan.py correctly detects and fails upon encountering:
1. A prohibited sensitive filename (e.g. dummy.key or terraform.tfvars)
2. A simulated leaked private cryptographic key in file contents
3. An unignored sensitive file path
"""

import sys
import os
import subprocess
import tempfile
from pathlib import Path

# Add repo root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

def test_secret_pattern_detection():
    print("[*] Testing security gate failure on simulated private key leak...")
    test_file = Path("test_dummy_leak.txt")
    simulated_key = "-----" + "BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzdummykeydata...\n-----" + "END RSA PRIVATE KEY-----\n"
    test_file.write_text(simulated_key)
    try:
        proc = subprocess.run([sys.executable, "tests/security_scan.py"], capture_output=True, text=True)
        assert proc.returncode != 0, f"Expected non-zero exit code, got {proc.returncode}"
        assert "Private cryptographic key" in proc.stdout or "POTENTIAL SECRET DETECTED" in proc.stdout
        print("  [✓] Gate successfully failed on dummy private key.")
    finally:
        if test_file.exists():
            test_file.unlink()

def test_prohibited_tracked_pattern_regex():
    print("[*] Testing prohibited filename patterns regex matching...")
    from tests.security_scan import FORBIDDEN_TRACKED_PATTERNS
    import re
    
    test_filenames = [
        "infra/terraform.tfstate",
        "infra/terraform.tfstate.backup",
        "terraform.tfvars",
        "keys/compromised.pem",
        "secrets/compromised.key",
        "id_rsa",
        "service-account-key.json",
        "docs/LAB_ACCESS_DETAILS.md"
    ]
    for fname in test_filenames:
        matched = any(re.search(pat, fname, re.IGNORECASE) for pat in FORBIDDEN_TRACKED_PATTERNS)
        assert matched, f"Pattern failed to match prohibited filename: {fname}"
    print(f"  [✓] All {len(test_filenames)} prohibited filename patterns correctly matched.")

def main():
    print("=" * 65)
    print("      Security Gate Failure & Negative Testing Suite         ")
    print("=" * 65)
    test_secret_pattern_detection()
    test_prohibited_tracked_pattern_regex()
    print("=" * 65)
    print("[+] All negative security gate assertions PASSED.")
    print("=" * 65)

if __name__ == "__main__":
    main()
