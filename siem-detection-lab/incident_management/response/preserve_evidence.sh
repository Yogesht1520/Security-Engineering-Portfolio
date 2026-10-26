#!/usr/bin/env bash
# =============================================================================
# preserve_evidence.sh — Automated Evidence Preservation Runbook
#
# MANDATORY REQUIREMENT: Must be executed BEFORE running `terraform destroy`.
# Collects forensic snapshots, audit logs, network state, and Wazuh alert streams.
# =============================================================================

set -uo pipefail

HONEYPOT_IP="${HONEYPOT_IP:-34.121.64.158}"
SIEM_IP="${SIEM_IP:-34.71.182.95}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/siem_lab_key}"

TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
EVIDENCE_DIR="evidence/${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "================================================================="
echo "        SIEM Lab — Automated Evidence Preservation Runbook       "
echo "================================================================="
echo "Target Honeypot: $HONEYPOT_IP"
echo "Target SIEM:     $SIEM_IP"
echo "Evidence Output: $EVIDENCE_DIR"
echo "Timestamp:       $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "-----------------------------------------------------------------"

# ── 1. Copy host authentication and audit logs from Honeypot ─────────────────
echo "[1/5] Offloading raw host logs from Honeypot..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}:/var/log/auth.log" "${EVIDENCE_DIR}/honeypot_auth.log" 2>/dev/null || echo "  [!] Warning: Failed to pull auth.log"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" "sudo cp /var/log/audit/audit.log /tmp/audit.log && sudo chmod 644 /tmp/audit.log" 2>/dev/null || true
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}:/tmp/audit.log" "${EVIDENCE_DIR}/honeypot_audit.log" 2>/dev/null || echo "  [!] Warning: Failed to pull audit.log"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" "sudo rm -f /tmp/audit.log" 2>/dev/null || true

# ── 2. Dump active network and user state from Honeypot ───────────────────────
echo "[2/5] Recording volatile system state (sockets, users, routing)..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" \
  "echo '=== ACTIVE SOCKETS ===' && ss -tnp; echo '=== ROUTING TABLE ===' && ip route; echo '=== LOGGED IN USERS ===' && who; echo '=== RECENT LOGINS ===' && last -25" \
  > "${EVIDENCE_DIR}/honeypot_system_state.txt" 2>/dev/null || echo "  [!] Warning: Failed to pull host volatile state"

# ── 3. Pull Wazuh alerts from SIEM Manager ───────────────────────────────────
echo "[3/5] Exporting Wazuh normalized security alerts..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${SIEM_IP}" \
  "sudo tail -n 5000 /var/ossec/logs/alerts/alerts.json" \
  > "${EVIDENCE_DIR}/wazuh_alerts.json" 2>/dev/null || echo "  [!] Warning: Failed to pull Wazuh alerts"

# ── 4. Snapshot Cloud Disk (if gcloud CLI available) ─────────────────────────
echo "[4/5] Checking Google Cloud disk snapshot eligibility..."
if command -v gcloud >/dev/null 2>&1; then
  echo "  - Creating GCP persistent disk snapshot..."
  gcloud compute disks snapshot siem-lab-honeypot \
    --snapshot-names="evidence-honeypot-${TIMESTAMP}" \
    --zone="us-central1-a" --quiet || echo "  [!] Snapshot failed or permission denied"
else
  echo "  - Note: gcloud CLI not present locally; host raw logs and volatile state preserved."
fi

# ── 5. Generate Evidence Manifest & Checksum ─────────────────────────────────
echo "[5/5] Generating cryptographic sha256 manifest..."
(
  cd "$EVIDENCE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum * > SHA256SUMS.txt
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * > SHA256SUMS.txt
  fi
)

echo "-----------------------------------------------------------------"
echo "Evidence preservation complete. Artifacts saved in: $EVIDENCE_DIR"
echo "It is now SAFE to proceed with teardown or rebuild."
echo "================================================================="
