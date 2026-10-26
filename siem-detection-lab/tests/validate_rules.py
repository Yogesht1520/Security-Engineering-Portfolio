#!/usr/bin/env python3
"""
validate_rules.py — Wazuh Custom Rule Linter & Static Quality Gate

Validates:
1. Well-formed XML syntax across all custom rule definitions.
2. Rule ID uniqueness (no collisions between files).
3. Rule ID range enforcement (custom IDs must reside in 100000–109999).
4. Required attribute and element presence (id, level, description).
"""

import sys
import glob
import xml.etree.ElementTree as ET
from pathlib import Path

CUSTOM_RULES_DIR = Path("wazuh/custom_rules")
CUSTOM_ID_MIN = 100000
CUSTOM_ID_MAX = 109999

def validate_all_rules():
    print("=" * 65)
    print("        Wazuh Custom Rules Static Quality & Syntax Gate         ")
    print("=" * 65)

    rule_files = sorted(CUSTOM_RULES_DIR.glob("*.xml"))
    if not rule_files:
        print(f"[!] ERROR: No XML rule files found in {CUSTOM_RULES_DIR}")
        return False

    seen_rule_ids = {}
    has_errors = False
    total_rules = 0

    for file_path in rule_files:
        print(f"\n[+] Inspecting: {file_path}")
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f"  [X] XML Syntax Error in {file_path}: {e}")
            has_errors = True
            continue

        if root.tag != "group":
            print(f"  [X] Error: Root element must be <group>, found <{root.tag}>")
            has_errors = True

        rules = root.findall(".//rule")
        if not rules:
            print(f"  [!] Warning: No <rule> elements found in {file_path}")

        for rule in rules:
            total_rules += 1
            rule_id = rule.get("id")
            level = rule.get("level")

            # 1. Attribute presence
            if not rule_id:
                print(f"  [X] Rule missing required 'id' attribute in {file_path}")
                has_errors = True
                continue
            if not level:
                print(f"  [X] Rule {rule_id} missing required 'level' attribute in {file_path}")
                has_errors = True

            # 2. Rule ID integer check
            try:
                rule_id_int = int(rule_id)
            except ValueError:
                print(f"  [X] Rule ID '{rule_id}' is not a valid integer in {file_path}")
                has_errors = True
                continue

            # 3. Rule ID range check
            if not (CUSTOM_ID_MIN <= rule_id_int <= CUSTOM_ID_MAX):
                print(f"  [X] Rule ID {rule_id_int} out of custom range [{CUSTOM_ID_MIN}-{CUSTOM_ID_MAX}] in {file_path}")
                has_errors = True

            # 4. Duplicate ID check
            if rule_id_int in seen_rule_ids:
                print(f"  [X] DUPLICATE Rule ID {rule_id_int} found in {file_path}! (Already defined in {seen_rule_ids[rule_id_int]})")
                has_errors = True
            else:
                seen_rule_ids[rule_id_int] = file_path.name

            # 5. Required <description> tag
            desc = rule.find("description")
            if desc is None or not (desc.text and desc.text.strip()):
                print(f"  [X] Rule {rule_id_int} missing non-empty <description> element in {file_path}")
                has_errors = True
            else:
                print(f"  [✓] Rule {rule_id_int} (Level {level}): {desc.text.strip()[:50]}...")

    print("\n" + "=" * 65)
    print(f"Audit Summary: {total_rules} rules inspected across {len(rule_files)} files.")
    if has_errors:
        print("[!] RESULT: FAILED — Rule validation errors detected.")
        print("=" * 65)
        return False
    else:
        print("[+] RESULT: PASSED — All rules satisfy syntax, uniqueness & range checks.")
        print("=" * 65)
        return True

if __name__ == "__main__":
    success = validate_all_rules()
    sys.exit(0 if success else 1)
