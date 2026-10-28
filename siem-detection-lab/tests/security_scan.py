#!/usr/bin/env python3
"""
security_scan.py — Repository Security & Secret Leakage Gate (History-Aware)

Verifies:
1. Prohibited sensitive files are not tracked in git (*.tfstate*, *.tfvars, *.pem, *.key, id_rsa).
2. Codebase files are free from hardcoded private keys, GCP service accounts, or tokens.
3. Full Git commit history (git log -p) is scanned for leaked credentials across past commits.
4. Effective .gitignore enforcement is tested using `git check-ignore` on synthetic sensitive paths.
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
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private cryptographic key"),
    (re.compile(r'"type":\s*"service_account"'), "GCP Service Account JSON key"),
    (re.compile(r'AIza[0-9A-Za-z\\-_]{35}'), "Google API Key"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "GitHub Personal Access Token"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), "Slack API Token"),
    (re.compile(r'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9._-]{15,}\.[A-Za-z0-9._-]+'), "JWT Secret Token"),
]

EXCLUDED_DIRS = {".git", ".terraform", "node_modules", ".pytest_cache", "__pycache__"}

def get_tracked_files():
    try:
        output = subprocess.check_output(["git", "ls-files"], text=True)
        return output.strip().splitlines()
    except Exception as e:
        print(f"[!] FATAL: git ls-files failed: {e}. Failing closed.")
        sys.exit(1)

def scan_tracked_filenames(tracked_files):
    print("[1/4] Scanning git tracked files for prohibited sensitive filenames...")
    violations = []
    for filepath in tracked_files:
        for pattern in FORBIDDEN_TRACKED_PATTERNS:
            if re.search(pattern, filepath, re.IGNORECASE):
                if filepath.endswith(".example") or filepath.endswith(".template"):
                    continue
                violations.append((filepath, pattern))
                print(f"  [X] PROHIBITED FILE TRACKED: {filepath} matches '{pattern}'")
    if not violations:
        print("  [✓] Zero prohibited files tracked in git index.")
    return len(violations) == 0

def scan_file_contents():
    print("\n[2/4] Scanning working tree files for leaked secrets & private keys...")
    violations = []
    repo_root = Path(".")
    
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix in [".png", ".jpg", ".webp", ".zip", ".tar", ".gz"]:
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
            except Exception:
                pass
                
    if not violations:
        print("  [✓] Zero credentials or private keys detected in working directory.")
    return len(violations) == 0

def scan_git_history():
    print("\n[3/4] Scanning complete Git commit history for siem-detection-lab (fail-closed)...")
    try:
        log_diff = subprocess.check_output(
            ["git", "log", "-p", "--full-history", "--", "."],
            text=True,
            errors="ignore"
        )
    except Exception as e:
        print(f"  [X] FATAL: Git history inspection failed: {e}. Failing closed.")
        return False

    violations = []
    for line in log_diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added_content = line[1:]
            for pattern, desc in LEAK_REGEXES:
                if pattern.search(added_content):
                    if "security_scan.py" in added_content or "AIza[0-9" in added_content or "DEMO" in added_content or "test_security_gate_negative" in added_content:
                        continue
                    violations.append((desc, line[:60]))
                    print(f"  [X] HISTORICAL SECRET DETECTED in commit history: {desc}")
                    break

    if not violations:
        print("  [✓] Zero secrets detected across complete Git commit history.")
    return len(violations) == 0

def check_effective_gitignore():
    print("\n[4/4] Verifying effective Git ignore behavior via `git check-ignore`...")
    test_paths = [
        "infra/terraform/terraform.tfstate",
        "infra/terraform/terraform.tfstate.backup",
        "infra/terraform/terraform.tfvars",
        "docs/LAB_ACCESS_DETAILS.md",
        "id_rsa",
        "private_key.pem",
        "service-account-credentials.json"
    ]
    
    all_ignored = True
    for p in test_paths:
        res = subprocess.run(["git", "check-ignore", "-q", p])
        if res.returncode == 0:
            print(f"  [✓] {p} is correctly ignored by Git.")
        else:
            print(f"  [X] FAILURE: {p} is NOT ignored by Git!")
            all_ignored = False
            
    return all_ignored

def main():
    print("=" * 65)
    print("      Repository Security, Secret & History Audit Gate       ")
    print("=" * 65)
    
    tracked_files = get_tracked_files()
    pass_files = scan_tracked_filenames(tracked_files)
    pass_contents = scan_file_contents()
    pass_history = scan_git_history()
    pass_gitignore = check_effective_gitignore()
    
    all_passed = pass_files and pass_contents and pass_history and pass_gitignore
    print("\n" + "=" * 65)
    if all_passed:
        print("[+] SECURITY GATE RESULT: ALL AUDIT CHECKS PASSED [SUCCESS]")
        print("=" * 65)
        sys.exit(0)
    else:
        print("[!] SECURITY GATE RESULT: FAILED — Security violations detected!")
        print("=" * 65)
        sys.exit(1)

if __name__ == "__main__":
    main()
