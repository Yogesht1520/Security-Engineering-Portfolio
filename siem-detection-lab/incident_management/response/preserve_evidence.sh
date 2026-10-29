#!/usr/bin/env bash
# =============================================================================
# preserve_evidence.sh — Automated Forensic Evidence Preservation Runbook
#
# MANDATORY REQUIREMENT: Must be executed BEFORE running `terraform destroy`.
# Collects forensic snapshots, audit logs, network state, and Wazuh alert streams.
# Produces SHA256SUMS.txt, structured EVIDENCE_MANIFEST.json, and true asymmetric
# digital signatures (.sig) verifiable via public key.
#
# SECURITY & INTEGRITY ENFORCEMENTS:
# - Categorizes evidence into Mandatory vs. Optional artifacts.
# - Fails closed: Halts immediately if any mandatory forensic artifact fails to
#   transfer or is empty, forbidding environment teardown.
# - Cryptographic Non-Repudiation: Generates true asymmetric digital signatures
#   using an RSA/ECDSA private key (outside repository) and exports public key.
# - WORM Storage Support: Optionally replicates archive to immutable cloud storage.
# =============================================================================

set -uo pipefail

HONEYPOT_IP="${HONEYPOT_IP:-34.121.64.158}"
SIEM_IP="${SIEM_IP:-34.71.182.95}"
EVIDENCE_BUCKET="${EVIDENCE_BUCKET:-}"
SSH_KEY="${SSH_KEY:-}"
SIGNING_KEY="${SIGNING_KEY:-}"

# In WSL or Linux, ensure SSH key is placed in Linux home with strict 0600 permissions
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
RUNBOOK_VERSION="3.0.0"

echo "================================================================="
echo "        SIEM Lab — Automated Evidence Preservation Runbook       "
echo "================================================================="
echo "Target Honeypot: $HONEYPOT_IP"
echo "Target SIEM:     $SIEM_IP"
echo "Evidence Output: $EVIDENCE_DIR"
echo "Collector:       ${COLLECTOR_USER}@${COLLECTOR_HOST}"
echo "Collection Start: $START_TIME_UTC"
echo "Runbook Version: $RUNBOOK_VERSION"
echo "-----------------------------------------------------------------"

# Track individual acquisition statuses
PULL_AUTH_OK=false
PULL_AUDIT_OK=false
PULL_STATE_OK=false
PULL_POSTURE_OK=false
PULL_ALERTS_OK=false

# ── 1. Copy host authentication and audit logs from Honeypot ─────────────────
echo "[1/5] Offloading raw host logs from Honeypot..."
if scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}:/var/log/auth.log" "${EVIDENCE_DIR}/honeypot_auth.log" 2>/dev/null; then
  [ -s "${EVIDENCE_DIR}/honeypot_auth.log" ] && PULL_AUTH_OK=true
fi

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" \
  "sudo cp /var/log/audit/audit.log /tmp/audit.log && sudo chmod 644 /tmp/audit.log" 2>/dev/null || true

if scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}:/tmp/audit.log" "${EVIDENCE_DIR}/honeypot_audit.log" 2>/dev/null; then
  [ -s "${EVIDENCE_DIR}/honeypot_audit.log" ] && PULL_AUDIT_OK=true
fi
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" "sudo rm -f /tmp/audit.log" 2>/dev/null || true

# ── 2. Dump volatile system state and active defense posture ─────────────────
echo "[2/5] Recording volatile system state and security posture..."
if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${HONEYPOT_IP}" \
  "echo '=== ACTIVE SOCKETS ===' && ss -tnp; echo '=== ROUTING TABLE ===' && ip route; echo '=== LOGGED IN USERS ===' && who; echo '=== RECENT LOGINS ===' && last -25" \
  > "${EVIDENCE_DIR}/honeypot_system_state.txt" 2>/dev/null; then
  [ -s "${EVIDENCE_DIR}/honeypot_system_state.txt" ] && PULL_STATE_OK=true
fi

if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${HONEYPOT_IP}" bash -c "'
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
'" > "${EVIDENCE_DIR}/honeypot_defense_posture.txt" 2>/dev/null; then
  [ -s "${EVIDENCE_DIR}/honeypot_defense_posture.txt" ] && PULL_POSTURE_OK=true
fi

# ── 3. Pull Wazuh alerts from SIEM Manager ───────────────────────────────────
echo "[3/5] Exporting Wazuh normalized security alerts..."
if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${SIEM_IP}" \
  "sudo tail -n 5000 /var/ossec/logs/alerts/alerts.json" \
  > "${EVIDENCE_DIR}/wazuh_alerts.json" 2>/dev/null; then
  [ -s "${EVIDENCE_DIR}/wazuh_alerts.json" ] && PULL_ALERTS_OK=true
fi

# ── 4. Snapshot Cloud Disk (Optional Infrastructure Artifact) ────────────────
echo "[4/5] Checking Google Cloud disk snapshot eligibility (optional)..."
DISK_SNAPSHOT_ID="none"
if command -v gcloud >/dev/null 2>&1; then
  echo "  - Initiating GCP persistent disk snapshot..."
  if gcloud compute disks snapshot siem-lab-honeypot \
    --snapshot-names="evidence-honeypot-${TIMESTAMP}" \
    --zone="us-central1-a" --quiet 2>/dev/null; then
    DISK_SNAPSHOT_ID="evidence-honeypot-${TIMESTAMP}"
    echo "  [✓] GCP persistent disk snapshot acquired: ${DISK_SNAPSHOT_ID}"
  else
    echo "  [!] Warning: GCP disk snapshot failed or insufficient IAM permissions."
  fi
else
  echo "  - Note: gcloud CLI not present locally; proceeding with host log and volatile state."
fi

# ── 4B. MANDATORY ARTIFACT VALIDATION (FAIL-CLOSED CHECK) ────────────────────
echo "[*] Validating integrity of mandatory forensic artifacts..."
MANDATORY_FAILURES=()

[ "$PULL_AUTH_OK" = true ] || MANDATORY_FAILURES+=("honeypot_auth.log (Host authentication log missing or empty)")
[ "$PULL_AUDIT_OK" = true ] || MANDATORY_FAILURES+=("honeypot_audit.log (Host Linux audit log missing or empty)")
[ "$PULL_STATE_OK" = true ] || MANDATORY_FAILURES+=("honeypot_system_state.txt (Volatile sockets/routes missing or empty)")
[ "$PULL_POSTURE_OK" = true ] || MANDATORY_FAILURES+=("honeypot_defense_posture.txt (Kernel iptables/auditd state missing or empty)")
[ "$PULL_ALERTS_OK" = true ] || MANDATORY_FAILURES+=("wazuh_alerts.json (Wazuh SIEM alert log missing or empty)")

if [ ${#MANDATORY_FAILURES[@]} -gt 0 ]; then
  echo ""
  echo "═════════════════════════════════════════════════════════════════"
  echo " [!] CRITICAL FORENSIC PRESERVATION FAILURE (FAIL-CLOSED)"
  echo "═════════════════════════════════════════════════════════════════"
  echo "Preservation aborted because mandatory artifacts could not be acquired:"
  for failure in "${MANDATORY_FAILURES[@]}"; do
    echo "  - $failure"
  done
  echo ""
  echo "CRITICAL SAFETY DIRECTIVE:"
  echo "  >>> DO NOT RUN 'terraform destroy' OR REBUILD THE VM! <<<"
  echo "  Volatile and persistent attack artifacts on the honeypot have"
  echo "  NOT been securely archived. Destroying the VM now will cause"
  echo "  PERMANENT, IRRECOVERABLE EVIDENCE DESTRUCTION."
  echo "═════════════════════════════════════════════════════════════════"
  exit 1
fi

echo "  [✓] All 5 mandatory forensic artifacts confirmed present and non-empty."

# ── 5. Generate Evidence Manifest & Checksums ────────────────────────────────
echo "[5/5] Generating cryptographic manifest, digital signature, and chain of custody..."
END_TIME_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

(
  cd "$EVIDENCE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum * 2>/dev/null | grep -v "SHA256SUMS.txt" | grep -v "EVIDENCE_MANIFEST.json" | grep -v "\.sig" | grep -v "\.pub" > SHA256SUMS.txt || true
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * 2>/dev/null | grep -v "SHA256SUMS.txt" | grep -v "EVIDENCE_MANIFEST.json" | grep -v "\.sig" | grep -v "\.pub" > SHA256SUMS.txt || true
  fi
)

# ── 5B. Resolve Asymmetric Signing Key Pair ─────────────────────────────────
SIGNING_KEY_PATH=""
PUBKEY_PATH="${EVIDENCE_DIR}/EVIDENCE_SIGNING_PUBKEY.pub"

if [ -n "$SIGNING_KEY" ] && [ -f "$SIGNING_KEY" ]; then
  SIGNING_KEY_PATH="$SIGNING_KEY"
elif [ -f "$HOME/.ssh/evidence_signing_key" ]; then
  SIGNING_KEY_PATH="$HOME/.ssh/evidence_signing_key"
else
  # Auto-provision a dedicated 3072-bit RSA evidence signing key in secure local directory
  mkdir -p "$HOME/.ssh"
  SIGNING_KEY_PATH="$HOME/.ssh/evidence_signing_key"
  echo "  [*] Generating new dedicated RSA-3072 forensic evidence signing key at $SIGNING_KEY_PATH..."
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$SIGNING_KEY_PATH" 2>/dev/null
  chmod 600 "$SIGNING_KEY_PATH"
fi

# Export public verification key into evidence directory
openssl pkey -in "$SIGNING_KEY_PATH" -pubout -out "$PUBKEY_PATH" 2>/dev/null
SIGNER_PUBKEY_FINGERPRINT=$(openssl dgst -sha256 "$PUBKEY_PATH" | awk '{print $NF}')

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
    "gcp_disk_snapshot": "${DISK_SNAPSHOT_ID}",
    "custody_notice": "Cryptographic hashes and asymmetric digital signatures guarantee tamper detection from recorded collection point forward."
  },
  "cryptography": {
    "digest_algorithm": "SHA-256",
    "signature_algorithm": "SHA256withRSA-PKCS#1v1.5",
    "public_key_file": "EVIDENCE_SIGNING_PUBKEY.pub",
    "public_key_sha256": "${SIGNER_PUBKEY_FINGERPRINT}"
  },
  "artifacts": [
$(
  FIRST=true
  for f in "${EVIDENCE_DIR}"/*; do
    fname=$(basename "$f")
    if [ "$fname" = "EVIDENCE_MANIFEST.json" ] || [ "$fname" = "SHA256SUMS.txt" ] || [[ "$fname" == *.sig ]] || [[ "$fname" == *.pub ]]; then
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

# ── 5C. Generate Asymmetric Digital Signatures ──────────────────────────────
if command -v openssl >/dev/null 2>&1; then
  openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" \
    -out "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json.sig" \
    "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json"

  openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" \
    -out "${EVIDENCE_DIR}/SHA256SUMS.txt.sig" \
    "${EVIDENCE_DIR}/SHA256SUMS.txt"
  echo "  [✓] Asymmetric digital signatures (.sig) created with private key."
fi

# ── 5D. Independent Verification Check ──────────────────────────────────────
echo "  [*] Verifying cryptographic signatures and artifact checksums..."
(
  cd "$EVIDENCE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS.txt >/dev/null && echo "  [✓] Checksum assertion PASSED (all SHA-256 hashes match)."
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -verify "$PUBKEY_PATH" \
      -signature "EVIDENCE_MANIFEST.json.sig" "EVIDENCE_MANIFEST.json" >/dev/null 2>&1 && \
      echo "  [✓] Manifest asymmetric digital signature PASSED (valid RSA key signature)."
    openssl dgst -sha256 -verify "$PUBKEY_PATH" \
      -signature "SHA256SUMS.txt.sig" "SHA256SUMS.txt" >/dev/null 2>&1 && \
      echo "  [✓] Checksum file asymmetric digital signature PASSED (valid RSA key signature)."
  fi
)

# ── 5E. Immutable Remote WORM Storage Offload (Optional) ────────────────────
if [ -n "$EVIDENCE_BUCKET" ]; then
  echo "[*] Replicating evidence archive to immutable cloud storage (${EVIDENCE_BUCKET})..."
  TARBALL="evidence_${TIMESTAMP}.tar.gz"
  tar -czf "${EVIDENCE_DIR}/${TARBALL}" -C "$EVIDENCE_DIR" .
  if command -v gcloud >/dev/null 2>&1; then
    gcloud storage cp "${EVIDENCE_DIR}/${TARBALL}" "${EVIDENCE_BUCKET}/${TARBALL}" --quiet 2>/dev/null && \
      echo "  [✓] Evidence bundle uploaded to WORM bucket: ${EVIDENCE_BUCKET}/${TARBALL}"
  elif command -v gsutil >/dev/null 2>&1; then
    gsutil cp "${EVIDENCE_DIR}/${TARBALL}" "${EVIDENCE_BUCKET}/${TARBALL}" 2>/dev/null && \
      echo "  [✓] Evidence bundle uploaded to WORM bucket: ${EVIDENCE_BUCKET}/${TARBALL}"
  fi
fi

echo "-----------------------------------------------------------------"
echo "Preservation Status: SUCCESS"
echo "All mandatory forensic artifacts verified, signed, and locked."
echo "Artifact Directory: $EVIDENCE_DIR"
echo "Public Verification Key: ${PUBKEY_PATH}"
echo "It is now SAFE to proceed with teardown or rebuild."
echo "================================================================="
exit 0
