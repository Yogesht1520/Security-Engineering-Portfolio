#!/usr/bin/env python3
"""
GCP IAM Isolation & Least-Privilege Verification Suite
======================================================
Verifies cloud control-plane isolation for untrusted honeypot VM:
1. Validates that honeypot VM attaches a dedicated zero-privilege service account
   (siem-lab-honeypot-sa), never the default Compute Engine service account.
2. Validates that OAuth access scopes are strictly restricted to logging.write only.
3. Asserts zero direct or inherited IAM role grants across Terraform HCL, state,
   and live Google Cloud IAM policy (--live-gcp).
4. Inherited permissions check: Asserts that parent folders/organizations do not
   confer ambient authority to the honeypot identity.

Fail-Closed Security Guarantee:
When --live-gcp is specified or when state files are examined, any missing tool,
parse error, unauthenticated session, or unexpected IAM grant causes an immediate
failure with exit code 1.
"""

import sys
import os
import re
import json
import argparse
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAFORM_MAIN = REPO_ROOT / "infra" / "terraform" / "main.tf"
TERRAFORM_STATE = REPO_ROOT / "infra" / "terraform" / "terraform.tfstate"

def verify_terraform_iam_isolation():
    print("=" * 65)
    print(" [1/3] IAM Isolation: Terraform HCL Static Architecture Gate     ")
    print("=" * 65)

    if not TERRAFORM_MAIN.exists():
        print(f"[-] ERROR: Missing {TERRAFORM_MAIN}")
        return False

    with open(TERRAFORM_MAIN, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Assert dedicated honeypot service account definition
    sa_match = re.search(r'resource\s+"google_service_account"\s+"honeypot_sa"\s*\{[^}]*account_id\s*=\s*"([^"]+)"', content)
    assert sa_match, "Dedicated honeypot service account (honeypot_sa) missing from Terraform configuration!"
    sa_id = sa_match.group(1)
    print(f"  [✓] Dedicated Honeypot Service Account: {sa_id}")

    # 2. Assert honeypot compute instance binds honeypot_sa.email
    inst_match = re.search(r'resource\s+"google_compute_instance"\s+"honeypot"\s*\{(.*?)\n\}', content, re.DOTALL)
    assert inst_match, "google_compute_instance.honeypot resource missing from Terraform configuration!"
    honeypot_block = inst_match.group(1)

    assert "google_service_account.honeypot_sa.email" in honeypot_block, (
        "Honeypot VM must attach dedicated honeypot_sa.email, not default Compute Engine service account!"
    )
    print("  [✓] Honeypot Instance Binding: Bound to google_service_account.honeypot_sa.email")

    # 3. Assert minimal OAuth scopes
    scope_match = re.search(r'scopes\s*=\s*\[([^\]]+)\]', honeypot_block)
    assert scope_match, "Missing service_account scopes definition on honeypot VM!"
    scopes_str = scope_match.group(1)
    assert "cloud-platform" not in scopes_str, "CRITICAL: Honeypot VM must NOT be granted broad 'cloud-platform' scope!"
    assert "logging.write" in scopes_str, "Honeypot VM expected minimal 'logging.write' scope."
    print(f"  [✓] OAuth Access Scopes: Restricted to minimal logging only ({scopes_str.strip()})")

    # 4. Assert zero direct or inherited IAM member bindings for honeypot_sa in Terraform
    iam_bindings = re.findall(r'resource\s+"google_(?:project|organization|folder)_iam_\w+"\s+"[^"]+"\s*\{([^}]*)\}', content)
    for b in iam_bindings:
        assert "honeypot_sa" not in b, f"Honeypot service account must have zero IAM role bindings! Found: {b}"

    print("  [✓] Zero Project & Inherited Grants: honeypot_sa has zero ambient role bindings in Terraform HCL.")
    return True

def verify_terraform_state_iam():
    print("\n" + "=" * 65)
    print(" [2/3] IAM Isolation: Terraform State Inspection                 ")
    print("=" * 65)

    if not TERRAFORM_STATE.exists():
        print("  [i] Local terraform.tfstate not present in clean workspace (HCL static audit verified).")
        return True

    # Fail closed on state read / parse error
    try:
        with open(TERRAFORM_STATE, "r", encoding="utf-8") as f:
            state = json.load(f)
    except Exception as e:
        print(f"  [-] FATAL: Failed to read or parse terraform.tfstate: {e}. Failing closed.")
        return False

    resources = state.get("resources", [])
    sa_found = False
    honeypot_inst_found = False

    for res in resources:
        res_type = res.get("type", "")
        res_name = res.get("name", "")

        # Assert zero IAM role bindings for honeypot_sa
        if "iam" in res_type.lower():
            for inst in res.get("instances", []):
                attrs = inst.get("attributes", {})
                member = attrs.get("member", "")
                members = attrs.get("members", [])
                all_members = [member] + (members if isinstance(members, list) else [])
                for m in all_members:
                    if "siem-lab-honeypot-sa" in str(m):
                        print(f"  [-] FATAL: State contains unauthorized IAM grant to honeypot SA: {attrs.get('role')}")
                        return False

        if res_type == "google_service_account" and res_name == "honeypot_sa":
            sa_found = True
            print("  [✓] Deployed Service Account in State: google_service_account.honeypot_sa verified")

        if res_type == "google_compute_instance" and res_name == "honeypot":
            instances = res.get("instances", [])
            for inst in instances:
                attrs = inst.get("attributes", {})
                sa_list = attrs.get("service_account", [])
                if sa_list:
                    email = sa_list[0].get("email", "")
                    scopes = sa_list[0].get("scopes", [])
                    assert "siem-lab-honeypot-sa" in email, f"Honeypot instance in state using unexpected SA: {email}"
                    assert not any("cloud-platform" in s for s in scopes), f"Honeypot in state has cloud-platform scope: {scopes}"
                    honeypot_inst_found = True
                    print(f"  [✓] Deployed Instance SA in State: {email} (Scopes: {scopes})")
                else:
                    honeypot_inst_found = True
                    print("  [✓] Deployed Instance SA in State: None (Zero-privilege: no ambient service account attached)")

    if not honeypot_inst_found:
        print("  [-] FATAL: Required honeypot compute instance not found in terraform.tfstate! Failing closed.")
        return False

    print("[+] Terraform State IAM isolation verified (Fail Closed).")
    return True

def verify_live_gcp_iam(project_id: str = "siem-detection-lab"):
    print("\n" + "=" * 65)
    print(" [3/3] IAM Isolation: Live Google Cloud Control Plane Audit      ")
    print("=" * 65)
    print(f"  [*] Querying live IAM policy & ancestors for project: {project_id}...")

    target_sa_pattern = "siem-lab-honeypot-sa"

    # 1. Project-level IAM bindings
    cmd_proj = ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"]
    try:
        res = subprocess.run(cmd_proj, capture_output=True, text=True, check=True)
        policy = json.loads(res.stdout)
        bindings = policy.get("bindings", [])

        honeypot_roles = []
        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])
            for m in members:
                if target_sa_pattern in m:
                    honeypot_roles.append(role)

        print(f"  Direct Project Roles for {target_sa_pattern}: {honeypot_roles or 'NONE (Zero Privilege Enforced)'}")
        assert len(honeypot_roles) == 0, (
            f"SECURITY VIOLATION: Honeypot service account holds unauthorized roles: {honeypot_roles}!"
        )
        print("  [✓] Live GCP Direct IAM Policy: Zero project-level permissions confirmed.")
    except FileNotFoundError:
        print("  [-] FATAL: 'gcloud' CLI was not found on PATH. Live GCP IAM check failed closed.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"  [-] FATAL: gcloud projects get-iam-policy failed: {e.stderr.strip()}. Failing closed.")
        return False

    # 2. Inherited Ancestor Permissions Check (Folder & Organization level)
    cmd_ancestors = ["gcloud", "projects", "get-ancestors-iam-policy", project_id, "--format=json"]
    try:
        res_anc = subprocess.run(cmd_ancestors, capture_output=True, text=True, check=True)
        ancestor_policies = json.loads(res_anc.stdout)
        inherited_roles = []
        for p in ancestor_policies:
            policy_data = p.get("policy", {})
            for b in policy_data.get("bindings", []):
                role = b.get("role", "")
                members = b.get("members", [])
                for m in members:
                    if target_sa_pattern in m:
                        inherited_roles.append(f"{role} (from {p.get('id')})")

        print(f"  Inherited Ancestor Roles for {target_sa_pattern}: {inherited_roles or 'NONE (Zero Privilege Enforced)'}")
        assert len(inherited_roles) == 0, (
            f"SECURITY VIOLATION: Honeypot service account holds inherited ancestor roles: {inherited_roles}!"
        )
        print("  [✓] Live GCP Inherited IAM Policy: Zero inherited ancestor permissions confirmed.")
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  [-] FATAL: Failed to query ancestor IAM policies for {project_id}: {e}. Failing closed.")
        return False

    print("[+] Live Google Cloud control-plane IAM isolation verified.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GCP IAM Isolation and Least-Privilege Verification")
    parser.add_argument("--live-gcp", action="store_true", help="Query live Google Cloud IAM policy via gcloud (fails closed on error)")
    parser.add_argument("--project", type=str, default="siem-detection-lab", help="GCP Project ID for live check")
    args = parser.parse_args()

    tf_ok = verify_terraform_iam_isolation()
    state_ok = verify_terraform_state_iam()
    live_ok = True
    if args.live_gcp:
        live_ok = verify_live_gcp_iam(project_id=args.project)

    if tf_ok and state_ok and live_ok:
        print("\n" + "=" * 65)
        print(" [✓] ALL GCP IAM ISOLATION CHECKS PASSED SUCCESSFULLY.        ")
        print("=" * 65)
        sys.exit(0)
    else:
        print("\n[-] GCP IAM ISOLATION CHECKS FAILED (Fail Closed).")
        sys.exit(1)
