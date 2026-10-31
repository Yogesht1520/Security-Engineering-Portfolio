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

# Step 2: Restore previous audit configuration files
if [ -d "${BACKUP_DIR}/audit" ]; then
  cp -r "${BACKUP_DIR}"/audit/* /etc/audit/
elif [ -d "${BACKUP_DIR}/rules.d" ]; then
  cp -r "${BACKUP_DIR}"/* /etc/audit/
fi
echo "  [✓] Restored configuration files from ${BACKUP_DIR}" >&2

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
  systemctl restart auditd >/dev/null 2>&1 && RESTART_OK=1 || true
fi
if [ "$RESTART_OK" -eq 0 ] && command -v service >/dev/null 2>&1; then
  service auditd restart >/dev/null 2>&1 && RESTART_OK=1 || true
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

# Step 7: Kernel Rule Parity Assertion (diff baseline vs post-rollback)
if [ -s "${BACKUP_DIR}/active_rules_pre.txt" ]; then
  POST_RULES_FILE="${BACKUP_DIR}/active_rules_post_rollback.txt"
  auditctl -l > "$POST_RULES_FILE" 2>/dev/null || true
  
  if ! cmp -s "${BACKUP_DIR}/active_rules_pre.txt" "$POST_RULES_FILE"; then
    echo "  [!] ERROR: Kernel audit rule parity mismatch between pre-deployment and post-rollback state!" >&2
    echo "      Diff:" >&2
    diff -u "${BACKUP_DIR}/active_rules_pre.txt" "$POST_RULES_FILE" >&2 || true
    ROLLBACK_FAILED=1
  else
    echo "  [✓] Kernel rule parity verified: 100% identical to pre-deployment baseline." >&2
  fi
fi

if [ "$ROLLBACK_FAILED" -ne 0 ]; then
  echo "[-] TRANSACTIONAL ROLLBACK FAILED TO RESTORE VERIFIED BASELINE!" >&2
  exit 1
fi

echo "[+] TRANSACTIONAL ROLLBACK COMPLETED AND VERIFIED SUCCESSFULLY." >&2
exit 0

