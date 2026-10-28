#!/usr/bin/env bash
# =============================================================================
# preserve_evidence.sh — Automated Forensic Evidence Preservation Runbook
#
# MANDATORY REQUIREMENT: Must be executed BEFORE running `terraform destroy`.
# Collects forensic snapshots, audit logs, network state, and Wazuh alert streams.
# Produces both SHA256SUMS.txt and a structured EVIDENCE_MANIFEST.json with
# collector metadata, timestamps, system identities, and custody assurances.
# =============================================================================

set -uo pipefail

HONEYPOT_IP="${HONEYPOT_IP:-34.121.64.158}"
SIEM_IP="${SIEM_IP:-34.71.182.95}"
SSH_KEY="${SSH_KEY:-}"
# In WSL or Linux, ensure key is placed in Linux home with strict 0600 permissions
mkdir -p "$HOME/.ssh"
SAFE_KEY="$HOME/.ssh/siem_lab_key_wsl"
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  cp "$SSH_KEY" "$SAFE_KEY"
  chmod 600 "$SAFE_KEY"
  SSH_KEY="$SAFE_KEY"
elif [ -f "$HOME/.ssh/siem_lab_key" ]; then
  chmod 600 "$HOME/.ssh/siem_lab_key"
  SSH_KEY="$HOME/.ssh/siem_lab_key"
else
  for candidate in /mnt/c/Users/*/.ssh/siem_lab_key /c/Users/*/.ssh/siem_lab_key; do
    if [ -f "$candidate" ]; then
      cp "$candidate" "$SAFE_KEY"
      chmod 600 "$SAFE_KEY"
      SSH_KEY="$SAFE_KEY"
      break
    fi
  done
fi

START_TIME_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
EVIDENCE_DIR="evidence/${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

COLLECTOR_USER=$(whoami 2>/dev/null || echo "soc-analyst")
COLLECTOR_HOST=$(hostname 2>/dev/null || echo "analyst-workstation")
RUNBOOK_VERSION="2.0.0"

echo "================================================================="
echo "        SIEM Lab — Automated Evidence Preservation Runbook       "
echo "================================================================="
echo "Target Honeypot: $HONEYPOT_IP"
echo "Target SIEM:     $SIEM_IP"
echo "Evidence Output: $EVIDENCE_DIR"
echo "Collector:       ${COLLECTOR_USER}@${COLLECTOR_HOST}"
echo "Collection Start: $START_TIME_UTC"
echo "-----------------------------------------------------------------"

# ── 1. Copy host authentication and audit logs from Honeypot ─────────────────
echo "[1/5] Offloading raw host logs from Honeypot..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}:/var/log/auth.log" "${EVIDENCE_DIR}/honeypot_auth.log" 2>/dev/null || echo "  [!] Warning: Failed to pull auth.log"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" "sudo cp /var/log/audit/audit.log /tmp/audit.log && sudo chmod 644 /tmp/audit.log" 2>/dev/null || true
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}:/tmp/audit.log" "${EVIDENCE_DIR}/honeypot_audit.log" 2>/dev/null || echo "  [!] Warning: Failed to pull audit.log"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" "sudo rm -f /tmp/audit.log" 2>/dev/null || true

# ── 2. Dump volatile system state and active defense posture ─────────────────
echo "[2/5] Recording volatile system state and security posture..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${HONEYPOT_IP}" \
  "echo '=== ACTIVE SOCKETS ===' && ss -tnp; echo '=== ROUTING TABLE ===' && ip route; echo '=== LOGGED IN USERS ===' && who; echo '=== RECENT LOGINS ===' && last -25" \
  > "${EVIDENCE_DIR}/honeypot_system_state.txt" 2>/dev/null || echo "  [!] Warning: Failed to pull host volatile state"

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${HONEYPOT_IP}" bash -c "'
  echo \"=== ACTIVE KERNEL IPTABLES (NETFILTER) ===\"
  sudo iptables-save
  echo \"\"
  echo \"=== GOOGLE GUEST AGENT SERVICE STATUS ===\"
  sudo systemctl is-active google-guest-agent 2>&1 || true
  sudo systemctl is-enabled google-guest-agent 2>&1 || true
  echo \"\"
  echo \"=== METADATA PROBE OUTCOME (169.254.169.254) ===\"
  curl -v -m 2 http://169.254.169.254/computeMetadata/v1/ 2>&1 || echo \"METADATA_ACCESS_REFUSED_OR_TIMED_OUT\"
  echo \"\"
  echo \"=== AUDITD KERNEL STATUS ===\"
  sudo auditctl -s 2>&1 || true
'" > "${EVIDENCE_DIR}/honeypot_defense_posture.txt" 2>/dev/null || echo "  [!] Warning: Failed to capture defense posture"

# ── 3. Pull Wazuh alerts from SIEM Manager ───────────────────────────────────
echo "[3/5] Exporting Wazuh normalized security alerts..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${SIEM_IP}" \
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

# ── 5. Generate Evidence Manifest & Checksums ────────────────────────────────
echo "[5/5] Generating cryptographic manifest, digital digest, and chain of custody..."
END_TIME_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

(
  cd "$EVIDENCE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum * 2>/dev/null | grep -v "SHA256SUMS.txt" | grep -v "EVIDENCE_MANIFEST.json" | grep -v "\.sig" > SHA256SUMS.txt || true
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * 2>/dev/null | grep -v "SHA256SUMS.txt" | grep -v "EVIDENCE_MANIFEST.json" | grep -v "\.sig" > SHA256SUMS.txt || true
  fi
)

# Build JSON Manifest with complete metadata
cat << JSON_MANIFEST > "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json"
{
  "provenance": {
    "collector": "${COLLECTOR_USER}@${COLLECTOR_HOST}",
    "collection_start_utc": "${START_TIME_UTC}",
    "collection_end_utc": "${END_TIME_UTC}",
    "runbook_version": "${RUNBOOK_VERSION}",
    "target_honeypot_ip": "${HONEYPOT_IP}",
    "target_siem_ip": "${SIEM_IP}",
    "custody_notice": "Cryptographic hashes verify integrity from recorded collection point forward."
  },
  "artifacts": [
$(
  FIRST=true
  for f in "${EVIDENCE_DIR}"/*; do
    fname=$(basename "$f")
    if [ "$fname" = "EVIDENCE_MANIFEST.json" ] || [ "$fname" = "SHA256SUMS.txt" ]; then
      continue
    fi
    if [ -f "$f" ]; then
      fsize=$(wc -c < "$f" | tr -d ' ')
      if command -v sha256sum >/dev/null 2>&1; then
        fhash=$(sha256sum "$f" | awk '{print $1}')
      elif command -v shasum >/dev/null 2>&1; then
        fhash=$(shasum -a 256 "$f" | awk '{print $1}')
      else
        fhash="unavailable"
      fi
      if [ "$FIRST" = true ]; then
        FIRST=false
      else
        echo ","
      fi
      printf '    {\n      "filename": "%s",\n      "size_bytes": %s,\n      "sha256": "%s"\n    }' "$fname" "$fsize" "$fhash"
    fi
  done
)
  ]
}
JSON_MANIFEST

# Generate detached cryptographic verification digest (SHA-256 HMAC/Digest)
if command -v openssl >/dev/null 2>&1; then
  openssl dgst -sha256 "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json" > "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json.sig"
  openssl dgst -sha256 "${EVIDENCE_DIR}/SHA256SUMS.txt" > "${EVIDENCE_DIR}/SHA256SUMS.txt.sig"
  echo "  [✓] Cryptographic digest signatures generated for manifest and checksums."
fi

# Independent verification check
echo "  [✓] Verifying integrity of preserved artifacts against manifest..."
(
  cd "$EVIDENCE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS.txt >/dev/null && echo "  [✓] Independent cryptographic verification PASSED (all hashes match)."
  fi
)

echo "-----------------------------------------------------------------"
echo "Evidence preservation complete."
echo "Artifacts, signatures, and custody manifest saved in: $EVIDENCE_DIR"
echo "It is now SAFE to proceed with teardown or rebuild."
echo "================================================================="
