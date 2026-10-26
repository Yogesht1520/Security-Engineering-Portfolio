#!/usr/bin/env python3
"""
security_scan.py — Repository Security & Secret Leakage Gate

Verifies:
1. No prohibited sensitive files are tracked in git (*.tfstate*, *.tfvars, *.pem, *.key, id_rsa).
2. No hardcoded private keys or GCP service account credentials exist in repo files.
3. .gitignore contains mandatory security exclusion patterns.
"""

import sys
import os
import re
import subprocess
from pathlib import Path

FORBIDDEN_TRACKED_PATTERNS = [
    r"\.tfstate$",
    r"\.tfstate\.backup$",
    r"terraform\.tfvars$",
    r"\.pem$",
    r"\.key$",
    r"id_rsa",
    r"service-account-.*\.json$",
    r"LAB_ACCESS_DETAILS\.md$",
    r".*PLAN.*\.md$",
    r".*REMEDIATION.*\.md$",
    r".*GAP_ANALYSIS.*\.md$",
]

LEAK_REGEXES = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private cryptographic key"),
    (re.compile(r'"type":\s*"service_account"'), "GCP Service Account JSON key"),
    (re.compile(r'AIza[0-9A-Za-z\\-_]{35}'), "Google API Key"),
]

EXCLUDED_DIRS = {".git", ".terraform", "node_modules", ".pytest_cache", "__pycache__"}

def get_tracked_files():
    try:
        output = subprocess.check_output(["git", "ls-files"], text=True)
        return output.strip().splitlines()
    except Exception as e:
        print(f"[!] Warning: git ls-files failed: {e}")
        return []

def scan_tracked_filenames(tracked_files):
    print("[1/3] Scanning git tracked files for prohibited sensitive filenames...")
    violations = []
    for filepath in tracked_files:
        for pattern in FORBIDDEN_TRACKED_PATTERNS:
            if re.search(pattern, filepath, re.IGNORECASE):
                # allow tfvars.example
                if filepath.endswith(".example") or filepath.endswith(".template"):
                    continue
                violations.append((filepath, pattern))
                print(f"  [X] PROHIBITED FILE TRACKED: {filepath} matches '{pattern}'")
    if not violations:
        print("  [✓] Zero prohibited files tracked in git index.")
    return len(violations) == 0

def scan_file_contents():
    print("\n[2/3] Scanning repository contents for leaked secrets & private keys...")
    violations = []
    repo_root = Path(".")
    
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            # Skip large logs or binary files
            if fpath.suffix in [".png", ".jpg", ".webp", ".zip", ".tar", ".gz", ".lock"]:
                continue
            
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for pattern, desc in LEAK_REGEXES:
                        if pattern.search(content):
                            # Exclude scanner script itself
                            if "security_scan.py" in str(fpath):
                                continue
                            violations.append((fpath, desc))
                            print(f"  [X] POTENTIAL SECRET DETECTED in {fpath}: {desc}")
            except Exception as e:
                pass
                
    if not violations:
        print("  [✓] Zero credentials, private keys, or API tokens detected in codebase.")
    return len(violations) == 0

def check_gitignore():
    print("\n[3/3] Checking .gitignore for mandatory security patterns...")
    gitignore_path = Path(".gitignore")
    if not gitignore_path.exists():
        print("  [X] Missing .gitignore file!")
        return False
        
    required_patterns = ["*.tfstate", "*.tfvars", "*.key", "*.pem", "service-account-"]
    content = gitignore_path.read_text(encoding="utf-8")
    missing = [pat for pat in required_patterns if pat not in content]
    
    if missing:
        print(f"  [X] .gitignore is missing mandatory patterns: {missing}")
        return False
    else:
        print("  [✓] .gitignore contains all mandatory security exclusion patterns.")
        return True

def main():
    print("=" * 65)
    print("           Repository Security & Secret Gatekeeper              ")
    print("=" * 65)
    
    tracked_files = get_tracked_files()
    pass_files = scan_tracked_filenames(tracked_files)
    pass_contents = scan_file_contents()
    pass_gitignore = check_gitignore()
    
    all_passed = pass_files and pass_contents and pass_gitignore
    print("\n" + "=" * 65)
    if all_passed:
        print("[+] SECURITY GATE RESULT: PASSED")
        print("=" * 65)
        sys.exit(0)
    else:
        print("[!] SECURITY GATE RESULT: FAILED — Security violations detected!")
        print("=" * 65)
        sys.exit(1)

if __name__ == "__main__":
    main()
