#!/usr/bin/env python3
"""
case_manager.py — Incident Case Lifecycle Management CLI (Enterprise-Hardened)

Provides end-to-end incident case tracking:
  --create: Opens a new case, runs autonomous GeoIP and reputation enrichment
  --list: Displays all open, contained, and closed cases
  --view: Shows full JSON details of a specific case
  --transition: Formally transitions case status with audit timeline entry
  --reopen: Privileged reopening of terminal cases with authorization seal
  --add-alert: Appends a Wazuh alert ID to an existing case
  --close: Formally closes a case with resolution notes

Security & Data Integrity Guarantees:
- Full JSON Schema validation against case_schema.json prior to every disk write
- IP syntactic validation (ipaddress module)
- Atomic file replacement (write-to-temp + os.replace) to prevent file corruption
- Strict state machine enforcement: Disallows ordinary transitions out of terminal states
- Privileged Reopen Governance: Requires explicit authorizer, justification, and SHA-256 seal
- Timezone-aware UTC timestamps
- Complete audit logging in the case timeline
"""

import os
import sys
import json
import hashlib
import argparse
import ipaddress
from datetime import datetime, timezone

import tempfile

try:
    import jsonschema
except ImportError:
    print("FATAL: Required dependency 'jsonschema' is missing. Failing closed to protect case integrity.")
    sys.exit(1)

# Import local enrichment modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enrichment.geoip import lookup_ip
from enrichment.reputation import check_reputation

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CASES_DIR = os.path.join(BASE_DIR, "cases")
SCHEMA_PATH = os.path.join(BASE_DIR, "case_schema.json")
os.makedirs(CASES_DIR, exist_ok=True)

# Valid status list and formal state machine transition rules
VALID_STATUSES = ["open", "investigating", "contained", "closed", "false_positive"]

# Strict transition matrix: Terminal states ('closed', 'false_positive') require privileged reopen
TRANSITION_MATRIX = {
    "open": ["investigating", "contained", "false_positive"],
    "investigating": ["contained", "closed", "false_positive"],
    "contained": ["investigating", "closed"],
    "closed": [],          # Ordinary transitions disallowed; requires privileged --reopen
    "false_positive": [],  # Ordinary transitions disallowed; requires privileged --reopen
}

def get_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def load_schema() -> dict:
    if os.path.exists(SCHEMA_PATH):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    raise FileNotFoundError(f"Case JSON schema not found at {SCHEMA_PATH}")

def validate_case_data(case: dict):
    """Enforces JSON Schema compliance before persisting to disk. Fails closed."""
    schema = load_schema()
    jsonschema.validate(instance=case, schema=schema)

def atomic_save_case(case_id: str, case_data: dict):
    """Writes to a collision-free temporary file first, validates schema, then atomically renames."""
    validate_case_data(case_data)
    filepath = os.path.join(CASES_DIR, f"{case_id}.json")
    
    with tempfile.NamedTemporaryFile("w", dir=CASES_DIR, delete=False, suffix=".tmp", encoding="utf-8") as tf:
        tmppath = tf.name
        json.dump(case_data, tf, indent=2)
    
    try:
        os.replace(tmppath, filepath)
    except Exception as e:
        if os.path.exists(tmppath):
            os.remove(tmppath)
        raise e

def get_next_case_id() -> str:
    year = datetime.now(timezone.utc).strftime("%Y")
    existing = [f for f in os.listdir(CASES_DIR) if f.startswith(f"CASE-{year}-") and f.endswith(".json")]
    if not existing:
        return f"CASE-{year}-001"
    
    max_num = 0
    for f in existing:
        try:
            num = int(f.replace(f"CASE-{year}-", "").replace(".json", ""))
            if num > max_num:
                max_num = num
        except ValueError:
            continue
    return f"CASE-{year}-{max_num + 1:03d}"

def create_case(title: str, severity: str, source_ip: str, analyst: str = "SOC Analyst") -> dict:
    clean_ip = source_ip.strip()
    try:
        ipaddress.ip_address(clean_ip)
    except ValueError as e:
        print(f"Error: Invalid IP address '{clean_ip}': {e}")
        sys.exit(1)

    case_id = get_next_case_id()
    opened_at = get_utc_now()

    print(f"[*] Running autonomous enrichment for {clean_ip}...")
    geo_data = lookup_ip(clean_ip)
    rep_data = check_reputation(clean_ip)

    case = {
        "case_id": case_id,
        "title": title,
        "status": "investigating",
        "severity": severity.lower(),
        "opened_at": opened_at,
        "closed_at": None,
        "source_ip": clean_ip,
        "geo": {
            "country": geo_data.get("country", "Unknown"),
            "city": geo_data.get("city", "Unknown"),
            "asn": geo_data.get("asn", "Unknown"),
            "isp": geo_data.get("isp", "Unknown")
        },
        "reputation": {
            "abuseipdb_score": rep_data.get("abuseipdb_score"),
            "total_reports": rep_data.get("total_reports"),
            "last_reported_at": rep_data.get("last_reported_at")
        },
        "wazuh_alert_ids": [],
        "target_users": [],
        "timeline": [
            {
                "timestamp": opened_at,
                "event": f"Case opened with severity {severity.upper()} targeting IP {clean_ip} by {analyst}"
            }
        ],
        "reopen_records": [],
        "containment_actions": [],
        "evidence_preserved": False,
        "analyst": analyst,
        "root_cause": "",
        "lessons_learned": ""
    }

    atomic_save_case(case_id, case)
    print(f"[+] Case created successfully: {case_id}")
    return case

def list_cases():
    files = sorted([f for f in os.listdir(CASES_DIR) if f.endswith(".json")])
    if not files:
        print("No cases found in incident_management/cases/")
        return

    print(f"{'CASE ID':<16} {'SEVERITY':<10} {'STATUS':<14} {'SOURCE IP':<18} {'TITLE'}")
    print("=" * 80)
    for fname in files:
        fpath = os.path.join(CASES_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            c = json.load(f)
            cid = c.get("case_id", "")
            sev = c.get("severity", "").upper()
            st = c.get("status", "")
            sip = c.get("source_ip", "")
            title = c.get("title", "")
            print(f"{cid:<16} {sev:<10} {st:<14} {sip:<18} {title}")

def view_case(case_id: str):
    fpath = os.path.join(CASES_DIR, f"{case_id}.json")
    if not os.path.exists(fpath):
        print(f"Error: Case {case_id} not found.")
        return
    with open(fpath, "r", encoding="utf-8") as f:
        print(json.dumps(json.load(f), indent=2))

def transition_case(case_id: str, new_status: str, notes: str = "", analyst: str = "SOC Analyst"):
    fpath = os.path.join(CASES_DIR, f"{case_id}.json")
    if not os.path.exists(fpath):
        print(f"Error: Case {case_id} not found.")
        sys.exit(1)
    with open(fpath, "r", encoding="utf-8") as f:
        case = json.load(f)

    clean_status = new_status.lower().strip()
    if clean_status not in VALID_STATUSES:
        print(f"Error: Invalid status '{clean_status}'. Must be one of: {VALID_STATUSES}")
        sys.exit(1)

    old_status = case.get("status", "open").lower().strip()

    # Guard: terminal cases cannot be reopened via regular transition
    if old_status in ["closed", "false_positive"]:
        print(f"Error: Disallowed transition out of terminal state '{old_status.upper()}'.")
        print("Privileged Governance: Reopening closed cases requires explicit authorization via --reopen.")
        sys.exit(1)

    allowed_transitions = TRANSITION_MATRIX.get(old_status, [])
    if clean_status != old_status and clean_status not in allowed_transitions:
        print(f"Error: Disallowed lifecycle transition from '{old_status.upper()}' to '{clean_status.upper()}'.")
        print(f"Allowed next states for {old_status.upper()} are: {[s.upper() for s in allowed_transitions]}")
        sys.exit(1)

    case["status"] = clean_status
    timestamp = get_utc_now()

    event_msg = f"Status transitioned from {old_status.upper()} to {clean_status.upper()} by {analyst}"
    if notes:
        event_msg += f". Notes: {notes}"
    case["timeline"].append({
        "timestamp": timestamp,
        "event": event_msg
    })

    if clean_status in ["closed", "false_positive"] and not case.get("closed_at"):
        case["closed_at"] = timestamp
        if notes:
            case["root_cause"] = notes

    atomic_save_case(case_id, case)
    print(f"[+] Case {case_id} transitioned to {clean_status.upper()}.")

def reopen_case(case_id: str, authorizer: str, justification: str, target_status: str = "investigating", analyst: str = "SOC Analyst"):
    """Privileged reopening of a closed or false-positive incident with immutable audit trail."""
    fpath = os.path.join(CASES_DIR, f"{case_id}.json")
    if not os.path.exists(fpath):
        print(f"Error: Case {case_id} not found.")
        sys.exit(1)
    with open(fpath, "r", encoding="utf-8") as f:
        case = json.load(f)

    old_status = case.get("status", "").lower().strip()
    if old_status not in ["closed", "false_positive"]:
        print(f"Error: Case {case_id} is currently in status '{old_status.upper()}' (not a closed terminal state). Use --transition instead.")
        sys.exit(1)

    clean_authorizer = authorizer.strip()
    if not clean_authorizer:
        print("Error: Privileged reopen REJECTED: --authorizer is required to identify the approving lead/manager.")
        sys.exit(1)

    clean_justification = justification.strip()
    if len(clean_justification) < 10:
        print("Error: Privileged reopen REJECTED: --justification must provide substantive operational reasoning (min 10 characters).")
        sys.exit(1)

    clean_target = target_status.lower().strip()
    if clean_target not in ["open", "investigating"]:
        print(f"Error: Invalid reopen target status '{clean_target}'. Must be 'open' or 'investigating'.")
        sys.exit(1)

    # Compute deterministic SHA-256 seal of the prior case state
    prior_state_canonical = json.dumps(case, sort_keys=True)
    prior_state_sha256 = hashlib.sha256(prior_state_canonical.encode("utf-8")).hexdigest()

    timestamp = get_utc_now()
    case["status"] = clean_target
    case["closed_at"] = None

    if "reopen_records" not in case:
        case["reopen_records"] = []

    reopen_entry = {
        "reopened_at": timestamp,
        "authorizer": clean_authorizer,
        "justification": clean_justification,
        "prior_status": old_status,
        "prior_state_sha256": prior_state_sha256
    }
    case["reopen_records"].append(reopen_entry)

    timeline_event = {
        "timestamp": timestamp,
        "event": f"PRIVILEGED REOPEN AUTHORIZED by {clean_authorizer} (Transitioned: {old_status.upper()} -> {clean_target.upper()}). Justification: {clean_justification} [Prior State Seal: {prior_state_sha256[:16]}...]",
        "authorizer": clean_authorizer,
        "justification": clean_justification
    }
    case["timeline"].append(timeline_event)

    atomic_save_case(case_id, case)
    print(f"[+] Case {case_id} REOPENED to status {clean_target.upper()} under authority of '{clean_authorizer}'.")
    print(f"    Cryptographic Prior State Seal: {prior_state_sha256}")
    return case

def add_alert_to_case(case_id: str, alert_id: str, analyst: str = "SOC Analyst"):
    fpath = os.path.join(CASES_DIR, f"{case_id}.json")
    if not os.path.exists(fpath):
        print(f"Error: Case {case_id} not found.")
        return
    with open(fpath, "r", encoding="utf-8") as f:
        case = json.load(f)

    if alert_id not in case["wazuh_alert_ids"]:
        case["wazuh_alert_ids"].append(alert_id)
        case["timeline"].append({
            "timestamp": get_utc_now(),
            "event": f"Linked Wazuh alert ID: {alert_id} by {analyst}"
        })
        atomic_save_case(case_id, case)
        print(f"[+] Alert {alert_id} added to case {case_id}.")
    else:
        print(f"Alert {alert_id} already linked to case {case_id}.")

def close_case(case_id: str, resolution: str, analyst: str = "SOC Analyst"):
    transition_case(case_id, "closed", notes=resolution, analyst=analyst)

def main():
    parser = argparse.ArgumentParser(description="SIEM Lab Incident Case Manager (Hardened)")
    parser.add_argument("--create", action="store_true", help="Create a new incident case")
    parser.add_argument("--title", type=str, help="Title of the incident case")
    parser.add_argument("--severity", type=str, choices=["low", "medium", "high", "critical"], default="high")
    parser.add_argument("--source-ip", type=str, help="Target attacker source IP")
    parser.add_argument("--analyst", type=str, default="SOC Analyst", help="Analyst handling the case")
    parser.add_argument("--list", action="store_true", help="List all tracked cases")
    parser.add_argument("--view", type=str, help="View case details by Case ID")
    parser.add_argument("--transition", nargs=2, metavar=("CASE_ID", "STATUS"), help="Standard lifecycle transition")
    parser.add_argument("--notes", type=str, default="", help="Optional notes for transition or resolution")
    parser.add_argument("--reopen", type=str, metavar="CASE_ID", help="Privileged reopen of a closed or false-positive case")
    parser.add_argument("--authorizer", type=str, default="", help="Identity of authority approving privileged reopen")
    parser.add_argument("--justification", type=str, default="", help="Substantive justification for privileged reopen")
    parser.add_argument("--target-status", type=str, default="investigating", choices=["open", "investigating"], help="Target status upon reopen")
    parser.add_argument("--add-alert", nargs=2, metavar=("CASE_ID", "ALERT_ID"), help="Link an alert to a case")
    parser.add_argument("--close", nargs=2, metavar=("CASE_ID", "RESOLUTION"), help="Close a case")

    args = parser.parse_args()

    if args.create:
        if not args.title or not args.source_ip:
            print("Error: --title and --source-ip are required when creating a case.")
            sys.exit(1)
        create_case(args.title, args.severity, args.source_ip, args.analyst)
    elif args.list:
        list_cases()
    elif args.view:
        view_case(args.view)
    elif args.transition:
        transition_case(args.transition[0], args.transition[1], notes=args.notes, analyst=args.analyst)
    elif args.reopen:
        reopen_case(args.reopen, authorizer=args.authorizer, justification=args.justification, target_status=args.target_status, analyst=args.analyst)
    elif args.add_alert:
        add_alert_to_case(args.add_alert[0], args.add_alert[1], analyst=args.analyst)
    elif args.close:
        close_case(args.close[0], args.close[1], analyst=args.analyst)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
