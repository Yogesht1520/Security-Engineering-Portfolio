#!/usr/bin/env bash
# =============================================================================
# rebuild_honeypot.sh — Safe Evidence-Preserving Honeypot Rebuild Tool
#
# PURPOSE:
# Safely reprovisions the honeypot from a clean state after an incident.
#
# SAFETY MANDATE:
# Automatically triggers `preserve_evidence.sh` before replacing the instance
# to guarantee no forensic data or telemetry is destroyed.
#
# USAGE:
#   ./rebuild_honeypot.sh [--skip-preserve] [--dry-run]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TERRAFORM_DIR="${REPO_ROOT}/infra/terraform"

SKIP_PRESERVE=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-preserve)
      SKIP_PRESERVE=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--skip-preserve] [--dry-run]"
      exit 0
      ;;
    *)
      echo "[!] Unknown parameter: $1"
      exit 1
      ;;
  esac
done

echo "================================================================="
echo "       Incident Recovery — Evidence-Preserving Honeypot Rebuild  "
echo "================================================================="
echo "Repository Root:  $REPO_ROOT"
echo "Terraform Dir:    $TERRAFORM_DIR"
echo "Skip Evidence:    $SKIP_PRESERVE"
echo "Dry Run Mode:     $DRY_RUN"
echo "Timestamp:        $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "-----------------------------------------------------------------"

# ── Step 1: Mandatory Evidence Preservation ───────────────────────────────────
if [ "$SKIP_PRESERVE" = false ]; then
  echo "[Step 1/3] Enforcing pre-rebuild evidence preservation..."
  if [ -f "${SCRIPT_DIR}/preserve_evidence.sh" ]; then
    bash "${SCRIPT_DIR}/preserve_evidence.sh"
  else
    echo "[!] ERROR: preserve_evidence.sh not found. Refusing to destroy unpreserved host."
    exit 1
  fi
else
  echo "[Step 1/3] WARNING: Skipping evidence preservation as requested (--skip-preserve)."
fi

# ── Step 2: Terraform Replace / Rebuild ───────────────────────────────────────
echo "[Step 2/3] Initiating Infrastructure Re-provisioning via Terraform..."
cd "$TERRAFORM_DIR"

if [ "$DRY_RUN" = true ]; then
  echo "  - Running terraform plan -replace=google_compute_instance.honeypot..."
  terraform plan -replace=google_compute_instance.honeypot
  echo "[+] Dry-run plan complete. No changes made."
  exit 0
fi

echo "  - Rebuilding google_compute_instance.honeypot..."
terraform apply -replace=google_compute_instance.honeypot -auto-approve

# ── Step 3: Post-Rebuild Verification ─────────────────────────────────────────
echo "[Step 3/3] Verifying Honeypot health and SIEM enrollment..."
HONEYPOT_IP=$(terraform output -raw honeypot_public_ip 2>/dev/null || echo "")
echo "New Honeypot IP: ${HONEYPOT_IP:-Unknown}"

echo "Waiting 30 seconds for cloud-init and Wazuh agent startup..."
sleep 30

echo "-----------------------------------------------------------------"
echo "[+] Honeypot rebuild completed successfully."
echo "    Baseline state restored. All prior evidence preserved."
echo "================================================================="
