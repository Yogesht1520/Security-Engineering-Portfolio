#!/usr/bin/env bash
# =============================================================================
# rollback_auditd.sh — Shared Production Auditd Rollback Engine
#
# PURPOSE:
# Atomically rolls back a failed auditd policy deployment to a verified prior state:
# 1. Purges candidate rules file from /etc/audit/rules.d/
# 2. Restores /etc/audit configuration directory from backup
# 3. Recompiles audit rules using augenrules --load (fails on compile error)
# 4. Restores active kernel audit rules from snapshot using auditctl -R
# 5. Restarts audit daemon, verifies 'enabled 1', and asserts bit-for-bit kernel
#    rule parity against the pre-deployment baseline snapshot.
#
# EXIT CODES:
#   0 = Rollback succeeded, daemon active, kernel rules 100% matched baseline.
#   1 = Rollback or verification assertion failed (FAIL-CLOSED).
#
# USAGE:
#   sudo ./rollback_auditd.sh <AUDIT_BACKUP_DIR> [CANDIDATE_RULE_FILE]
# =============================================================================

set -euo pipefail

BACKUP_DIR="${1:-}"
CANDIDATE_FILE="${2:-/etc/audit/rules.d/siem-lab.rules}"

if [ -z "$BACKUP_DIR" ] || [ ! -d "$BACKUP_DIR" ]; then
  echo "[!] ERROR: A valid backup directory must be supplied to rollback_auditd.sh." >&2
  echo "Usage: $0 <AUDIT_BACKUP_DIR> [CANDIDATE_RULE_FILE]" >&2
  exit 1
fi

echo "[*] INITIATING AUDITD TRANSACTIONAL ROLLBACK..." >&2

ROLLBACK_FAILED=0

# Step 1: Purge candidate rules file to prevent augenrules from re-compiling corrupt rules
if [ -f "$CANDIDATE_FILE" ]; then
  rm -f "$CANDIDATE_FILE"
  echo "  [✓] Purged candidate audit rules file: ${CANDIDATE_FILE}" >&2
fi

# Step 2: Safely and transactionally replace the entire audit configuration directory
# Preserves original directory permissions, ownership, and SELinux/file attributes.
AUDIT_DIR="${SIEM_AUDIT_DIR:-/etc/audit}"
SOURCE_AUDIT_DIR=""
if [ -d "${BACKUP_DIR}/audit" ]; then
  SOURCE_AUDIT_DIR="${BACKUP_DIR}/audit"
elif [ -d "${BACKUP_DIR}/rules.d" ]; then
  SOURCE_AUDIT_DIR="${BACKUP_DIR}"
fi

BROKEN_DIR="${AUDIT_DIR}.failed.$$"
if [ -n "$SOURCE_AUDIT_DIR" ]; then
  echo "  [*] Transactionally replacing entire ${AUDIT_DIR} configuration from ${SOURCE_AUDIT_DIR}..." >&2
  STAGE_DIR="${AUDIT_DIR}.rollback.$$"
  rm -rf "$STAGE_DIR" "$BROKEN_DIR"

  # Capture and preserve original directory permissions and ownership before swap
  ORIG_PERMS=""
  ORIG_OWNER=""
  if [ -d "$AUDIT_DIR" ]; then
    if command -v stat >/dev/null 2>&1; then
      ORIG_PERMS="$(stat -c "%a" "$AUDIT_DIR" 2>/dev/null || stat -f "%Lp" "$AUDIT_DIR" 2>/dev/null || echo "")"
      ORIG_OWNER="$(stat -c "%u:%g" "$AUDIT_DIR" 2>/dev/null || stat -f "%u:%g" "$AUDIT_DIR" 2>/dev/null || echo "")"
    fi
  fi

  mkdir -p "$STAGE_DIR"

  # Copy clean baseline into staging directory
  cp -a "${SOURCE_AUDIT_DIR}/." "$STAGE_DIR/"

  # Ensure candidate corrupt rule file is eradicated from staging rules.d
  CANDIDATE_NAME="$(basename "$CANDIDATE_FILE")"
  rm -f "${STAGE_DIR}/rules.d/${CANDIDATE_NAME}"

  # Preserve original permissions and ownership on staging directory
  if [ -d "$AUDIT_DIR" ]; then
    chmod --reference="$AUDIT_DIR" "$STAGE_DIR" 2>/dev/null || \
      ([ -n "$ORIG_PERMS" ] && chmod "$ORIG_PERMS" "$STAGE_DIR" 2>/dev/null) || \
      chmod 0750 "$STAGE_DIR" 2>/dev/null || true
    chown --reference="$AUDIT_DIR" "$STAGE_DIR" 2>/dev/null || \
      ([ -n "$ORIG_OWNER" ] && chown "$ORIG_OWNER" "$STAGE_DIR" 2>/dev/null) || true
  else
    chmod 0750 "$STAGE_DIR" 2>/dev/null || true
  fi

  if [ -d "${AUDIT_DIR}/rules.d" ] && [ -d "${STAGE_DIR}/rules.d" ]; then
    chmod --reference="${AUDIT_DIR}/rules.d" "${STAGE_DIR}/rules.d" 2>/dev/null || chmod 0750 "${STAGE_DIR}/rules.d" 2>/dev/null || true
    chown --reference="${AUDIT_DIR}/rules.d" "${STAGE_DIR}/rules.d" 2>/dev/null || true
  elif [ -d "${STAGE_DIR}/rules.d" ]; then
    chmod 0750 "${STAGE_DIR}/rules.d" 2>/dev/null || true
  fi

  # Atomic directory swap with explicit boundary verification
  SWAP_STEP1_OK=1
  if [ -d "$AUDIT_DIR" ]; then
    if [ "${SIEM_SIMULATE_SWAP_BOUNDARY_1_FAIL:-0}" = "1" ]; then
      echo "  [!] TEST HOOK: Simulating rename Boundary 1 failure (moving ${AUDIT_DIR} -> ${BROKEN_DIR})" >&2
      SWAP_STEP1_OK=0
    elif ! mv "$AUDIT_DIR" "$BROKEN_DIR" 2>/dev/null; then
      echo "  [!] FATAL: Boundary 1 failed: Could not rename ${AUDIT_DIR} to ${BROKEN_DIR}!" >&2
      SWAP_STEP1_OK=0
    fi
  fi

  if [ "$SWAP_STEP1_OK" -eq 0 ]; then
    echo "  [-] Rollback aborted at Boundary 1. Active configuration preserved in prior state." >&2
    rm -rf "$STAGE_DIR"
    ROLLBACK_FAILED=1
  else
    SWAP_STEP2_OK=1
    if [ "${SIEM_SIMULATE_SWAP_BOUNDARY_2_FAIL:-0}" = "1" ]; then
      echo "  [!] TEST HOOK: Simulating rename Boundary 2 failure (moving ${STAGE_DIR} -> ${AUDIT_DIR})" >&2
      SWAP_STEP2_OK=0
    elif ! mv "$STAGE_DIR" "$AUDIT_DIR" 2>/dev/null; then
      echo "  [!] FATAL: Boundary 2 failed: Could not rename ${STAGE_DIR} to ${AUDIT_DIR}!" >&2
      SWAP_STEP2_OK=0
    fi

    if [ "$SWAP_STEP2_OK" -eq 1 ]; then
      echo "  [✓] Replaced entire ${AUDIT_DIR} configuration directory from verified baseline (metadata & permissions preserved)." >&2
    else
      echo "  [!] Attempting emergency recovery from ${BROKEN_DIR} back to ${AUDIT_DIR}..." >&2
      if [ -d "$BROKEN_DIR" ]; then
        mv "$BROKEN_DIR" "$AUDIT_DIR" 2>/dev/null || true
      fi
      rm -rf "$STAGE_DIR"
      ROLLBACK_FAILED=1
    fi
  fi
fi

# Step 3: Recompile audit rules (fail-closed if augenrules fails)
echo "  [*] Recompiling audit rules via augenrules..." >&2
if ! augenrules --load >/dev/null 2>&1; then
  echo "  [!] ERROR: augenrules --load failed during rollback compilation!" >&2
  ROLLBACK_FAILED=1
fi

# Step 4: Re-apply kernel audit rules directly from pre-deployment snapshot if available
if [ -s "${BACKUP_DIR}/active_rules_pre.txt" ]; then
  echo "  [*] Restoring kernel audit rules from active_rules_pre.txt..." >&2
  if ! auditctl -R "${BACKUP_DIR}/active_rules_pre.txt" >/dev/null 2>&1; then
    echo "  [!] ERROR: auditctl -R failed to re-apply baseline kernel rules!" >&2
    ROLLBACK_FAILED=1
  else
    echo "  [✓] Re-applied active kernel audit rules from active_rules_pre.txt" >&2
  fi
fi

# Step 5: Restart daemon and assert running state
echo "  [*] Restarting audit daemon..." >&2
RESTART_OK=0
if command -v systemctl >/dev/null 2>&1; then
  if systemctl restart auditd >/dev/null 2>&1; then
    RESTART_OK=1
  fi
fi
if [ "$RESTART_OK" -eq 0 ] && command -v service >/dev/null 2>&1; then
  if service auditd restart >/dev/null 2>&1; then
    RESTART_OK=1
  fi
fi

if [ "$RESTART_OK" -eq 0 ]; then
  echo "  [!] ERROR: Failed to restart auditd daemon via systemctl or service!" >&2
  ROLLBACK_FAILED=1
fi

# Step 6: Assert daemon enabled status
if ! auditctl -s 2>/dev/null | grep -q "enabled 1"; then
  echo "  [!] ERROR: auditd daemon failed to report 'enabled 1' after rollback!" >&2
  ROLLBACK_FAILED=1
else
  echo "  [✓] Audit daemon status verified: active and enabled (enabled 1)." >&2
fi

# Step 7A: Full Filesystem Audit Configuration Parity Assertion
if [ -d "${BACKUP_DIR}/audit" ]; then
  echo "  [*] Comparing full filesystem audit configuration against baseline..." >&2
  if ! diff -r "${BACKUP_DIR}/audit" "$AUDIT_DIR" >&2; then
    echo "  [!] ERROR: Filesystem audit configuration mismatch between baseline and post-rollback state!" >&2
    ROLLBACK_FAILED=1
  else
    echo "  [✓] Filesystem audit configuration parity verified: 100% identical to baseline." >&2
  fi
elif [ -d "${BACKUP_DIR}/rules.d" ]; then
  echo "  [*] Comparing ${AUDIT_DIR}/rules.d/ against baseline..." >&2
  if ! diff -r "${BACKUP_DIR}/rules.d" "${AUDIT_DIR}/rules.d" >&2; then
    echo "  [!] ERROR: Audit rules directory mismatch between baseline and post-rollback state!" >&2
    ROLLBACK_FAILED=1
  else
    echo "  [✓] Audit rules directory parity verified: 100% identical to baseline." >&2
  fi
fi

# Step 7B: Kernel Rule Parity Assertion (diff baseline vs post-rollback)
if [ -s "${BACKUP_DIR}/active_rules_pre.txt" ]; then
  POST_RULES_FILE="${BACKUP_DIR}/active_rules_post_rollback.txt"
  if ! auditctl -l > "$POST_RULES_FILE" 2>/dev/null || [ ! -s "$POST_RULES_FILE" ]; then
    echo "  [!] ERROR: Failed to capture active post-rollback kernel rules (auditctl -l)!" >&2
    ROLLBACK_FAILED=1
  elif ! cmp -s "${BACKUP_DIR}/active_rules_pre.txt" "$POST_RULES_FILE"; then
    echo "  [!] ERROR: Kernel audit rule parity mismatch between pre-deployment and post-rollback state!" >&2
    echo "      Diff:" >&2
    diff -u "${BACKUP_DIR}/active_rules_pre.txt" "$POST_RULES_FILE" >&2 || true
    ROLLBACK_FAILED=1
  else
    echo "  [✓] Kernel rule parity verified: 100% identical to pre-deployment baseline." >&2
  fi
fi

if [ "$ROLLBACK_FAILED" -ne 0 ]; then
  if [ -n "${BROKEN_DIR:-}" ] && [ -d "${BROKEN_DIR:-}" ]; then
    echo "  [!] Preserving broken configuration for forensic diagnosis: ${BROKEN_DIR}" >&2
  fi
  echo "[-] TRANSACTIONAL ROLLBACK FAILED TO RESTORE VERIFIED BASELINE!" >&2
  exit 1
fi

if [ -n "${BROKEN_DIR:-}" ] && [ -d "${BROKEN_DIR:-}" ]; then
  rm -rf "$BROKEN_DIR"
fi

echo "[+] TRANSACTIONAL ROLLBACK COMPLETED AND VERIFIED SUCCESSFULLY." >&2
exit 0

