#!/usr/bin/env python3
"""
case_manager.py — Incident Case Lifecycle Management CLI

Provides end-to-end incident case tracking:
  --create: Opens a new case, runs autonomous GeoIP and reputation enrichment
  --list: Displays all open and closed cases
  --view: Shows full JSON details of a specific case
  --add-alert: Appends a Wazuh alert ID to an existing case
  --close: Formally closes a case with resolution notes
"""

import os
import sys
import json
import argparse
from datetime import datetime

# Import local enrichment modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enrichment.geoip import lookup_ip
from enrichment.reputation import check_reputation

CASES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")
os.makedirs(CASES_DIR, exist_ok=True)

def get_next_case_id() -> str:
    year = datetime.utcnow().strftime("%Y")
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
    case_id = get_next_case_id()
    opened_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"[*] Running autonomous enrichment for {source_ip}...")
    geo_data = lookup_ip(source_ip)
    rep_data = check_reputation(source_ip)

    case = {
        "case_id": case_id,
        "title": title,
        "status": "investigating",
        "severity": severity.lower(),
        "opened_at": opened_at,
        "closed_at": None,
        "source_ip": source_ip,
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
                "event": f"Case opened with severity {severity.upper()} targeting IP {source_ip}"
            }
        ],
        "containment_actions": [],
        "evidence_preserved": False,
        "analyst": analyst,
        "root_cause": "",
        "lessons_learned": ""
    }

    filepath = os.path.join(CASES_DIR, f"{case_id}.json")
    with open(filepath, "w") as f:
        json.dump(case, f, indent=2)

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
        with open(fpath, "r") as f:
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
    with open(fpath, "r") as f:
        print(json.dumps(json.load(f), indent=2))

def add_alert_to_case(case_id: str, alert_id: str):
    fpath = os.path.join(CASES_DIR, f"{case_id}.json")
    if not os.path.exists(fpath):
        print(f"Error: Case {case_id} not found.")
        return
    with open(fpath, "r") as f:
        case = json.load(f)

    if alert_id not in case["wazuh_alert_ids"]:
        case["wazuh_alert_ids"].append(alert_id)
        case["timeline"].append({
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": f"Linked Wazuh alert ID: {alert_id}"
        })
        with open(fpath, "w") as f:
            json.dump(case, f, indent=2)
        print(f"[+] Alert {alert_id} added to case {case_id}.")
    else:
        print(f"Alert {alert_id} already linked to case {case_id}.")

def close_case(case_id: str, resolution: str):
    fpath = os.path.join(CASES_DIR, f"{case_id}.json")
    if not os.path.exists(fpath):
        print(f"Error: Case {case_id} not found.")
        return
    with open(fpath, "r") as f:
        case = json.load(f)

    closed_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    case["status"] = "closed"
    case["closed_at"] = closed_at
    case["root_cause"] = resolution
    case["timeline"].append({
        "timestamp": closed_at,
        "event": f"Case closed with resolution: {resolution}"
    })

    with open(fpath, "w") as f:
        json.dump(case, f, indent=2)
    print(f"[+] Case {case_id} closed successfully.")

def main():
    parser = argparse.ArgumentParser(description="SIEM Lab Incident Case Manager")
    parser.add_argument("--create", action="store_true", help="Create a new incident case")
    parser.add_argument("--title", type=str, help="Title of the incident case")
    parser.add_argument("--severity", type=str, choices=["low", "medium", "high", "critical"], default="high")
    parser.add_argument("--source-ip", type=str, help="Target attacker source IP")
    parser.add_argument("--analyst", type=str, default="SOC Analyst", help="Analyst handling the case")
    parser.add_argument("--list", action="store_true", help="List all tracked cases")
    parser.add_argument("--view", type=str, help="View case details by Case ID")
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
    elif args.add_alert:
        add_alert_to_case(args.add_alert[0], args.add_alert[1])
    elif args.close:
        close_case(args.close[0], args.close[1])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
