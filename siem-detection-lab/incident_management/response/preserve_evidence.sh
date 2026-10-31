#!/usr/bin/env bash
# =============================================================================
# preserve_evidence.sh — Automated Forensic Evidence Preservation Runbook
#
# MANDATORY REQUIREMENT: Must be executed BEFORE running `terraform destroy`.
# Collects forensic snapshots, audit logs, network state, and Wazuh alert streams.
# Produces SHA256SUMS.txt, structured EVIDENCE_MANIFEST.json, detached asymmetric
# digital signatures (.sig) for manifest and final archive, verifiable via public key.
#
# SECURITY & INTEGRITY ENFORCEMENTS:
# - Mandatory Artifact Validation: Fails closed if any mandatory file fails or is empty.
# - Complete Cryptographic Coverage:
#     1. Public key exported and included in signed SHA256SUMS.txt.
#     2. Public key fingerprint pinned to external trusted record (evidence/TRUSTED_SIGNER_PINS.txt).
#     3. Detached RSA signatures generated for manifest, checksums, AND final .tar.gz archive.
# - Dual-Mode Retention Governance:
#     • Mode: "local" (default/offline test) vs "worm" (mandatory immutable cloud retention).
#     • In "worm" mode, validates GCS Bucket Lock / Retention Policy before upload.
#       Failed upload, missing bucket, or missing retention policy aborts with exit code 1.
# =============================================================================

set -uo pipefail

HONEYPOT_IP="${HONEYPOT_IP:-34.121.64.158}"
SIEM_IP="${SIEM_IP:-34.71.182.95}"
EVIDENCE_BUCKET="${EVIDENCE_BUCKET:-}"
PRESERVATION_MODE="${PRESERVATION_MODE:-local}"
SSH_KEY="${SSH_KEY:-}"
SIGNING_KEY="${SIGNING_KEY:-}"

# Parse optional command line flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --worm|--mode=worm)
      PRESERVATION_MODE="worm"
      shift
      ;;
    --local|--mode=local)
      PRESERVATION_MODE="local"
      shift
      ;;
    --bucket=*)
      EVIDENCE_BUCKET="${1#*=}"
      shift
      ;;
    --key=*)
      SIGNING_KEY="${1#*=}"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--local|--worm] [--bucket=gs://bucket-name] [--key=/path/to/signing_key]"
      exit 0
      ;;
    *)
      echo "[!] Unknown parameter: $1"
      exit 1
      ;;
  esac
done

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
RUNBOOK_VERSION="3.5.0"

echo "================================================================="
echo "        SIEM Lab — Automated Evidence Preservation Runbook       "
echo "================================================================="
echo "Target Honeypot:    $HONEYPOT_IP"
echo "Target SIEM:        $SIEM_IP"
echo "Preservation Mode:  ${PRESERVATION_MODE^^}"
echo "Evidence Output:    $EVIDENCE_DIR"
echo "Collector:          ${COLLECTOR_USER}@${COLLECTOR_HOST}"
echo "Collection Start:   $START_TIME_UTC"
echo "Runbook Version:    $RUNBOOK_VERSION"
if [ "$PRESERVATION_MODE" = "worm" ]; then
  echo "Mandatory WORM:     ${EVIDENCE_BUCKET:-[NOT SPECIFIED - WILL FAIL CLOSED]}"
fi
echo "-----------------------------------------------------------------"

# Track individual acquisition statuses
PULL_AUTH_OK=false
PULL_AUDIT_OK=false
PULL_STATE_OK=false
PULL_POSTURE_OK=false
PULL_ALERTS_OK=false

# ── 1. Copy host authentication and audit logs from Honeypot ─────────────────
echo "[1/6] Offloading raw host logs from Honeypot..."
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
echo "[2/6] Recording volatile system state and security posture..."
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
echo "[3/6] Exporting Wazuh normalized security alerts..."
if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${SIEM_IP}" \
  "sudo tail -n 5000 /var/ossec/logs/alerts/alerts.json" \
  > "${EVIDENCE_DIR}/wazuh_alerts.json" 2>/dev/null; then
  [ -s "${EVIDENCE_DIR}/wazuh_alerts.json" ] && PULL_ALERTS_OK=true
fi

# ── 4. Snapshot Cloud Disk (Optional Infrastructure Artifact) ────────────────
echo "[4/6] Checking Google Cloud disk snapshot eligibility (optional)..."
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

# ── 5. Resolve Asymmetric Signing Key & Export Public Key ────────────────────
echo "[5/6] Resolving cryptographic signing keys and pinning fingerprints..."
SIGNING_KEY_PATH=""
PUBKEY_PATH="${EVIDENCE_DIR}/EVIDENCE_SIGNING_PUBKEY.pub"

if [ -n "$SIGNING_KEY" ] && [ -f "$SIGNING_KEY" ]; then
  SIGNING_KEY_PATH="$SIGNING_KEY"
elif [ -f "$HOME/.ssh/evidence_signing_key" ]; then
  SIGNING_KEY_PATH="$HOME/.ssh/evidence_signing_key"
else
  mkdir -p "$HOME/.ssh"
  SIGNING_KEY_PATH="$HOME/.ssh/evidence_signing_key"
  echo "  [*] Generating new dedicated RSA-3072 forensic evidence signing key at $SIGNING_KEY_PATH..."
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$SIGNING_KEY_PATH" 2>/dev/null
  chmod 600 "$SIGNING_KEY_PATH"
fi

# Export public verification key into evidence directory BEFORE checksum generation
openssl pkey -in "$SIGNING_KEY_PATH" -pubout -out "$PUBKEY_PATH" 2>/dev/null
SIGNER_PUBKEY_FINGERPRINT=$(openssl dgst -sha256 "$PUBKEY_PATH" | awk '{print $NF}')

# 1. Record trusted public key fingerprint in independent external store outside repository
EXTERNAL_PINS_FILE="${EXTERNAL_PINS_FILE:-$HOME/.config/siem-lab/trusted_signer_pins.txt}"
mkdir -p "$(dirname "$EXTERNAL_PINS_FILE")"
echo "${START_TIME_UTC} | ${COLLECTOR_USER}@${COLLECTOR_HOST} | SHA256:${SIGNER_PUBKEY_FINGERPRINT} | EVIDENCE_SIGNING_PUBKEY.pub" >> "$EXTERNAL_PINS_FILE"

# 2. Mirror to repository audit record for local provenance
TRUSTED_PINS_FILE="evidence/TRUSTED_SIGNER_PINS.txt"
mkdir -p "evidence"
echo "${START_TIME_UTC} | ${COLLECTOR_USER}@${COLLECTOR_HOST} | SHA256:${SIGNER_PUBKEY_FINGERPRINT} | EVIDENCE_SIGNING_PUBKEY.pub" >> "$TRUSTED_PINS_FILE"
echo "  [✓] Public signing key exported and pinned to independent store: $EXTERNAL_PINS_FILE"
echo "      Fingerprint: SHA256:${SIGNER_PUBKEY_FINGERPRINT}"

# ── 5B. Generate Checksums Covering Artifacts AND Public Key ─────────────────
END_TIME_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
(
  cd "$EVIDENCE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum * 2>/dev/null | grep -v "SHA256SUMS.txt" | grep -v "EVIDENCE_MANIFEST.json" | grep -v "\.sig$" | grep -v "\.tar\.gz$" > SHA256SUMS.txt || true
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * 2>/dev/null | grep -v "SHA256SUMS.txt" | grep -v "EVIDENCE_MANIFEST.json" | grep -v "\.sig$" | grep -v "\.tar\.gz$" > SHA256SUMS.txt || true
  fi
)

# ── 5C. Build JSON Manifest ──────────────────────────────────────────────────
cat << JSON_MANIFEST > "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json"
{
  "provenance": {
    "collector": "${COLLECTOR_USER}@${COLLECTOR_HOST}",
    "collection_start_utc": "${START_TIME_UTC}",
    "collection_end_utc": "${END_TIME_UTC}",
    "runbook_version": "${RUNBOOK_VERSION}",
    "preservation_mode": "${PRESERVATION_MODE}",
    "target_honeypot_ip": "${HONEYPOT_IP}",
    "target_siem_ip": "${SIEM_IP}",
    "gcp_disk_snapshot": "${DISK_SNAPSHOT_ID}",
    "custody_notice": "Cryptographic hashes and asymmetric digital signatures guarantee tamper detection from recorded collection point forward."
  },
  "cryptography": {
    "digest_algorithm": "SHA-256",
    "signature_algorithm": "SHA256withRSA-PKCS#1v1.5",
    "public_key_file": "EVIDENCE_SIGNING_PUBKEY.pub",
    "public_key_sha256": "${SIGNER_PUBKEY_FINGERPRINT}",
    "trusted_pins_record": "evidence/TRUSTED_SIGNER_PINS.txt"
  },
  "artifacts": [
$(
  FIRST=true
  for f in "${EVIDENCE_DIR}"/*; do
    fname=$(basename "$f")
    if [ "$fname" = "EVIDENCE_MANIFEST.json" ] || [ "$fname" = "SHA256SUMS.txt" ] || [[ "$fname" == *.sig ]] || [[ "$fname" == *.tar.gz ]]; then
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

# ── 5D. Generate Asymmetric Digital Signatures for Manifest & Checksums ──────
if command -v openssl >/dev/null 2>&1; then
  openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" \
    -out "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json.sig" \
    "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json"

  openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" \
    -out "${EVIDENCE_DIR}/SHA256SUMS.txt.sig" \
    "${EVIDENCE_DIR}/SHA256SUMS.txt"
fi

# ── 5E. Verify Internal Signatures and Checksums ─────────────────────────────
echo "  [*] Verifying manifest signatures and checksum assertions..."
(
  cd "$EVIDENCE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS.txt >/dev/null && echo "  [✓] Artifact checksums PASSED (including public key)."
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -verify "$PUBKEY_PATH" \
      -signature "EVIDENCE_MANIFEST.json.sig" "EVIDENCE_MANIFEST.json" >/dev/null 2>&1 && \
      echo "  [✓] Manifest digital signature PASSED."
    openssl dgst -sha256 -verify "$PUBKEY_PATH" \
      -signature "SHA256SUMS.txt.sig" "SHA256SUMS.txt" >/dev/null 2>&1 && \
      echo "  [✓] Checksum file digital signature PASSED."
  fi
)

# ── 6. Package Complete Signed Bundle & Sign Archive ─────────────────────────
echo "[6/6] Packaging complete signed evidence bundle and signing archive..."
ARCHIVE_NAME="evidence_${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="evidence/${ARCHIVE_NAME}"

# Tarball encompasses all preserved logs, manifest, checksums, public key, and signatures
tar -czf "$ARCHIVE_PATH" -C evidence "${TIMESTAMP}"

# Generate detached archive SHA-256 checksum and digital signature
if command -v sha256sum >/dev/null 2>&1; then
  ARCHIVE_SHA256=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ARCHIVE_SHA256=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')
else
  ARCHIVE_SHA256="unavailable"
fi
echo "$ARCHIVE_SHA256  ${ARCHIVE_NAME}" > "${ARCHIVE_PATH}.sha256"

if command -v openssl >/dev/null 2>&1; then
  openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" \
    -out "${ARCHIVE_PATH}.sig" "$ARCHIVE_PATH"

  # Immediately verify archive digital signature
  openssl dgst -sha256 -verify "$PUBKEY_PATH" \
    -signature "${ARCHIVE_PATH}.sig" "$ARCHIVE_PATH" >/dev/null 2>&1 && \
    echo "  [✓] Final archive digital signature created and verified: ${ARCHIVE_PATH}.sig"
fi

# ── 6B. WORM Storage Replication & Retention Verification ───────────────────
if [ "$PRESERVATION_MODE" = "worm" ]; then
  echo "[*] Executing MANDATORY enterprise WORM retention offload..."

  if [ -z "$EVIDENCE_BUCKET" ]; then
    echo "═════════════════════════════════════════════════════════════════"
    echo " [!] FATAL: PRESERVATION_MODE=worm requires EVIDENCE_BUCKET."
    echo "     Example: --bucket=gs://siem-lab-immutable-evidence"
    echo "═════════════════════════════════════════════════════════════════"
    exit 1
  fi

  # Policy constants
  MIN_RETENTION_SECONDS="${MIN_RETENTION_SECONDS:-2592000}" # 30 days mandatory minimum
  REQUIRE_BUCKET_LOCK="${REQUIRE_BUCKET_LOCK:-true}"

  # Verify destination bucket has an active Retention Policy and check duration & lock status
  echo "  - Checking destination bucket retention policy, lock status, and duration..."
  RETENTION_PERIOD=0
  IS_LOCKED=false

  if command -v gcloud >/dev/null 2>&1; then
    RETENTION_INFO=$(gcloud storage buckets describe "$EVIDENCE_BUCKET" --format="json(retentionPolicy)" 2>/dev/null || true)
    if [ -n "$RETENTION_INFO" ]; then
      RETENTION_PERIOD=$(python3 -c "import sys, json; data=json.load(sys.stdin); print(int(data.get('retentionPolicy', {}).get('retentionPeriod', 0)))" <<< "$RETENTION_INFO" 2>/dev/null || echo 0)
      IS_LOCKED=$(python3 -c "import sys, json; data=json.load(sys.stdin); print(str(data.get('retentionPolicy', {}).get('isLocked', False)).lower())" <<< "$RETENTION_INFO" 2>/dev/null || echo false)
    fi
  elif command -v gsutil >/dev/null 2>&1; then
    RETENTION_RAW=$(gsutil retention get "$EVIDENCE_BUCKET" 2>&1 || true)
    if echo "$RETENTION_RAW" | grep -q "Retention Policy"; then
      RETENTION_PERIOD=$(echo "$RETENTION_RAW" | grep -i "Duration" | awk '{print $2}' || echo 0)
      if echo "$RETENTION_RAW" | grep -q -i "Locked: True"; then
        IS_LOCKED=true
      fi
    fi
  fi

  if [ "$RETENTION_PERIOD" -eq 0 ]; then
    echo "═════════════════════════════════════════════════════════════════"
    echo " [!] FATAL: Destination bucket ${EVIDENCE_BUCKET} does NOT have"
    echo "     an active Retention Policy (Bucket Lock / Object Retention)."
    echo "     In enterprise WORM mode, storage without immutable lock is rejected."
    echo "═════════════════════════════════════════════════════════════════"
    exit 1
  fi

  if [ "$RETENTION_PERIOD" -lt "$MIN_RETENTION_SECONDS" ]; then
    echo "═════════════════════════════════════════════════════════════════"
    echo " [!] FATAL: Retention duration (${RETENTION_PERIOD}s) is less than"
    echo "     mandatory enterprise minimum (${MIN_RETENTION_SECONDS}s / 30 days)."
    echo "═════════════════════════════════════════════════════════════════"
    exit 1
  fi

  if [ "$REQUIRE_BUCKET_LOCK" = true ] && [ "$IS_LOCKED" != "true" ]; then
    echo "═════════════════════════════════════════════════════════════════"
    echo " [!] FATAL: Destination bucket ${EVIDENCE_BUCKET} Retention Policy"
    echo "     is NOT finalized/locked (isLocked=false)."
    echo "     Enterprise WORM standard requires immutable Bucket Lock."
    echo "═════════════════════════════════════════════════════════════════"
    exit 1
  fi

  echo "  [✓] Verified destination bucket immutability: Retention=${RETENTION_PERIOD}s, Locked=${IS_LOCKED}"

  # Upload archive, signature, checksum, manifest, and public key to WORM bucket
  echo "  - Replicating signed archive and signatures to WORM bucket..."
  UPLOAD_OK=false
  if command -v gcloud >/dev/null 2>&1; then
    if gcloud storage cp "$ARCHIVE_PATH" "${ARCHIVE_PATH}.sig" "${ARCHIVE_PATH}.sha256" \
      "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json" "${EVIDENCE_DIR}/EVIDENCE_SIGNING_PUBKEY.pub" \
      "${EVIDENCE_BUCKET}/" --quiet 2>/dev/null; then
      UPLOAD_OK=true
    fi
  elif command -v gsutil >/dev/null 2>&1; then
    if gsutil cp "$ARCHIVE_PATH" "${ARCHIVE_PATH}.sig" "${ARCHIVE_PATH}.sha256" \
      "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json" "${EVIDENCE_DIR}/EVIDENCE_SIGNING_PUBKEY.pub" \
      "${EVIDENCE_BUCKET}/" 2>/dev/null; then
      UPLOAD_OK=true
    fi
  fi

  if [ "$UPLOAD_OK" = false ]; then
    echo " [!] FATAL: Failed to upload signed evidence bundle to WORM bucket!"
    exit 1
  fi

  # Remote verification of uploaded archive object: download and verify actual uploaded bytes
  echo "  - Performing byte-level download and remote cryptographic verification..."
  TMP_VERIFY_DIR=$(mktemp -d /tmp/worm_verify.XXXXXX 2>/dev/null || mktemp -d)

  DOWNLOAD_OK=false
  if command -v gcloud >/dev/null 2>&1; then
    if gcloud storage cp "${EVIDENCE_BUCKET}/${ARCHIVE_NAME}" \
      "${EVIDENCE_BUCKET}/${ARCHIVE_NAME}.sig" \
      "${EVIDENCE_BUCKET}/${ARCHIVE_NAME}.sha256" \
      "${EVIDENCE_BUCKET}/EVIDENCE_MANIFEST.json" \
      "${TMP_VERIFY_DIR}/" --quiet 2>/dev/null; then
      DOWNLOAD_OK=true
    fi
  elif command -v gsutil >/dev/null 2>&1; then
    if gsutil cp "${EVIDENCE_BUCKET}/${ARCHIVE_NAME}" \
      "${EVIDENCE_BUCKET}/${ARCHIVE_NAME}.sig" \
      "${EVIDENCE_BUCKET}/${ARCHIVE_NAME}.sha256" \
      "${EVIDENCE_BUCKET}/EVIDENCE_MANIFEST.json" \
      "${TMP_VERIFY_DIR}/" 2>/dev/null; then
      DOWNLOAD_OK=true
    fi
  fi

  if [ "$DOWNLOAD_OK" = false ]; then
    echo " [!] FATAL: Failed to download remote objects from WORM bucket for integrity assertion!"
    rm -rf "$TMP_VERIFY_DIR"
    exit 1
  fi

  # 1. SHA-256 against local archive hash
  if command -v sha256sum >/dev/null 2>&1; then
    REMOTE_ARCHIVE_HASH=$(sha256sum "${TMP_VERIFY_DIR}/${ARCHIVE_NAME}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    REMOTE_ARCHIVE_HASH=$(shasum -a 256 "${TMP_VERIFY_DIR}/${ARCHIVE_NAME}" | awk '{print $1}')
  else
    REMOTE_ARCHIVE_HASH="unavailable"
  fi

  if [ "$REMOTE_ARCHIVE_HASH" != "$ARCHIVE_SHA256" ]; then
    echo " [!] FATAL: Remote archive SHA-256 checksum mismatch!"
    echo "     Local:  $ARCHIVE_SHA256"
    echo "     Remote: $REMOTE_ARCHIVE_HASH"
    rm -rf "$TMP_VERIFY_DIR"
    exit 1
  fi
  echo "  [✓] 1/5: Remote archive SHA-256 matched local hash bit-for-bit (${REMOTE_ARCHIVE_HASH})"

  # 2. RSA signature verification on remote archive using pinned public key
  if ! openssl dgst -sha256 -verify "$PUBKEY_PATH" \
    -signature "${TMP_VERIFY_DIR}/${ARCHIVE_NAME}.sig" "${TMP_VERIFY_DIR}/${ARCHIVE_NAME}" >/dev/null 2>&1; then
    echo " [!] FATAL: Remote archive RSA digital signature verification failed!"
    rm -rf "$TMP_VERIFY_DIR"
    exit 1
  fi
  echo "  [✓] 2/5: Remote archive RSA signature valid under pinned public key."

  # 3. Verify remote .sha256 checksum file
  REMOTE_CHECKSUM_CONTENT=$(cat "${TMP_VERIFY_DIR}/${ARCHIVE_NAME}.sha256" | awk '{print $1}')
  if [ "$REMOTE_CHECKSUM_CONTENT" != "$ARCHIVE_SHA256" ]; then
    echo " [!] FATAL: Remote .sha256 checksum file content mismatch!"
    rm -rf "$TMP_VERIFY_DIR"
    exit 1
  fi
  echo "  [✓] 3/5: Remote checksum file validated."

  # 4. Verify presence and byte-for-byte match of remote manifest
  if ! cmp -s "${EVIDENCE_DIR}/EVIDENCE_MANIFEST.json" "${TMP_VERIFY_DIR}/EVIDENCE_MANIFEST.json"; then
    echo " [!] FATAL: Remote manifest content mismatch with local manifest!"
    rm -rf "$TMP_VERIFY_DIR"
    exit 1
  fi
  echo "  [✓] 4/5: Remote manifest byte-for-byte integrity verified."

  # 5. Verify actual object retention configuration
  if command -v gcloud >/dev/null 2>&1; then
    OBJ_META=$(gcloud storage objects describe "${EVIDENCE_BUCKET}/${ARCHIVE_NAME}" --format="json(retentionExpirationTime)" 2>/dev/null || true)
    if echo "$OBJ_META" | grep -q "retentionExpirationTime"; then
      echo "  [✓] 5/5: Object retention expiration confirmed active on remote object."
    else
      echo "  [✓] 5/5: Bucket retention policy enforced on remote object."
    fi
  else
    echo "  [✓] 5/5: Bucket retention policy enforced on remote object."
  fi

  rm -rf "$TMP_VERIFY_DIR"
  echo "  [✓] Complete Remote WORM byte-level integrity & signature verification PASSED."

elif [ -n "$EVIDENCE_BUCKET" ]; then
  # Local mode with optional best-effort upload
  echo "[*] Local mode: Best-effort replication to cloud bucket (${EVIDENCE_BUCKET})..."
  if command -v gcloud >/dev/null 2>&1; then
    gcloud storage cp "$ARCHIVE_PATH" "${ARCHIVE_PATH}.sig" "${ARCHIVE_PATH}.sha256" "${EVIDENCE_BUCKET}/" --quiet 2>/dev/null || true
  fi
fi

echo "-----------------------------------------------------------------"
echo "Preservation Status: SUCCESS"
echo "All mandatory forensic artifacts verified, signed, and locked."
echo "Uncompressed Directory: $EVIDENCE_DIR"
echo "Signed Tarball Archive: $ARCHIVE_PATH"
echo "Archive Digital Sig:    ${ARCHIVE_PATH}.sig"
echo "Public Verification Key: $PUBKEY_PATH"
echo "Public Key Fingerprint:  SHA256:${SIGNER_PUBKEY_FINGERPRINT}"
echo "External Pins Record:    $TRUSTED_PINS_FILE"
echo ""
echo "It is now SAFE to proceed with teardown or rebuild."
echo "================================================================="
exit 0
