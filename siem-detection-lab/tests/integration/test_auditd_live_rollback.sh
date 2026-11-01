#!/usr/bin/env bash
# =============================================================================
# test_auditd_live_rollback.sh — Live Linux VM Auditd Integration Test Suite
#
# PURPOSE:
# Performs destructive failure injection on a live Linux kernel audit subsystem
# and validates automated recovery via infra/rollback_auditd.sh.
#
# SAFETY CONTROLS:
# - Strictly requires root (EUID == 0) and explicit confirmation flag:
#   --force-live-danger or DISPOSABLE_VM=true.
# - Captures active kernel rules (auditctl -l) prior to staging any candidate.
# - Traps EXIT, SIGINT, SIGTERM to guarantee host restoration.
# - Preserves recovery backup if recovery fails to prevent baseline destruction.
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FORCE_LIVE_DANGER=false

for arg in "$@"; do
  case "$arg" in
    --force-live-danger)
      FORCE_LIVE_DANGER=true
      ;;
  esac
done

if [ "${DISPOSABLE_VM:-false}" = "true" ]; then
  FORCE_LIVE_DANGER=true
fi

# SAFETY ENFORCEMENT
if [ "$FORCE_LIVE_DANGER" != true ]; then
  echo -e "${RED}[!] SAFETY BLOCKED: Live VM integration modifies /etc/audit/rules.d/ and reloads kernel rules.${NC}" >&2
  echo -e "    To execute on a dedicated, disposable lab instance, supply explicit confirmation:" >&2
  echo -e "    $0 --force-live-danger" >&2
  echo -e "    or set DISPOSABLE_VM=true." >&2
  exit 1
fi

if [ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]; then
  echo -e "${RED}[!] ERROR: Live integration test requires root privileges (sudo).${NC}" >&2
  exit 1
fi

echo -e "\n${BOLD}================================================================${NC}"
echo -e "${BOLD}   Auditd Live Linux VM Integration Test Suite                  ${NC}"
echo -e "${BOLD}   Execution Mode: Live Host & Kernel Subsystem (Disposable VM) ${NC}"
echo -e "${BOLD}================================================================${NC}\n"

INT_BACKUP="/var/backups/audit_live_test_$(date +%s)"
mkdir -p "$INT_BACKUP"
cp -r /etc/audit "$INT_BACKUP/"

# Fail-closed baseline requirement: Assert active non-empty rules baseline before modifying host
if ! auditctl -l > "${INT_BACKUP}/active_rules_pre.txt" 2>/dev/null || [ ! -s "${INT_BACKUP}/active_rules_pre.txt" ]; then
  echo -e "${RED}[!] FATAL: Failed to capture active non-empty kernel audit rules baseline (auditctl -l)! Aborting live test.${NC}" >&2
  rm -rf "$INT_BACKUP"
  exit 1
fi

CANDIDATE_DEST="/etc/audit/rules.d/siem-lab.rules"
PRE_EXISTED_SIEM_RULES=false
if [ -f "$CANDIDATE_DEST" ]; then
  PRE_EXISTED_SIEM_RULES=true
  cp "$CANDIDATE_DEST" "${INT_BACKUP}/pre_existing_siem-lab.rules"
  echo "  [*] Pre-existing candidate file detected and preserved: ${CANDIDATE_DEST}"
fi

CANDIDATE_CORRUPT="/tmp/live_corrupt_test.rules"
echo "-a invalid_action_flag -S execve -k broken" > "$CANDIDATE_CORRUPT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROD_ROLLBACK="${SCRIPT_DIR}/../../infra/rollback_auditd.sh"

# State Tracking & Idempotency Controls
ROLLBACK_ALREADY_RUN=false
CLEANUP_ALREADY_RUN=false
ROLLBACK_FAILED_STATE=0

# Exit Trap: Guarantees idempotent, single-execution host state restoration
cleanup_live_host() {
  if [ "$CLEANUP_ALREADY_RUN" = true ]; then
    return 0
  fi
  CLEANUP_ALREADY_RUN=true

  echo -e "\n${CYAN}[*] Running guaranteed live host exit trap cleanup (idempotent, single execution)...${NC}"
  rm -f "$CANDIDATE_CORRUPT"

  # Restore pre-existing candidate file if it was present before test; otherwise unlink candidate
  if [ "$PRE_EXISTED_SIEM_RULES" = true ] && [ -f "${INT_BACKUP}/pre_existing_siem-lab.rules" ]; then
    cp "${INT_BACKUP}/pre_existing_siem-lab.rules" "$CANDIDATE_DEST" 2>/dev/null || true
    echo "  [✓] Restored pre-existing candidate file state to $CANDIDATE_DEST"
  else
    rm -f "$CANDIDATE_DEST"
  fi

  # If rollback has NOT yet executed (e.g. premature failure or signal interruption), execute deferred rollback
  if [ "$ROLLBACK_ALREADY_RUN" = false ] && [ -d "$INT_BACKUP" ]; then
    echo "  [*] Executing deferred emergency rollback in exit trap..."
    if [ -f "$PROD_ROLLBACK" ]; then
      if ! bash "$PROD_ROLLBACK" "$INT_BACKUP" "$CANDIDATE_DEST"; then
        echo -e "${RED}[!] FATAL: Deferred emergency rollback failed during exit trap!${NC}" >&2
        ROLLBACK_FAILED_STATE=1
      else
        ROLLBACK_ALREADY_RUN=true
      fi
    else
      echo -e "${RED}[!] FATAL: Production rollback engine $PROD_ROLLBACK not found!${NC}" >&2
      ROLLBACK_FAILED_STATE=1
    fi
  fi

  # Verify post-restoration filesystem and kernel parity before concluding cleanup
  if [ -d "$INT_BACKUP" ]; then
    local post_rules
    post_rules=$(auditctl -l 2>/dev/null || true)
    local pre_rules
    pre_rules=$(cat "${INT_BACKUP}/active_rules_pre.txt" 2>/dev/null || true)
    if [ "$post_rules" != "$pre_rules" ]; then
      echo -e "${RED}[!] PARITY CHECK FAILURE: Kernel rules mismatch after cleanup!${NC}" >&2
      ROLLBACK_FAILED_STATE=1
    fi
    if [ -d "${INT_BACKUP}/audit" ] && [ -d /etc/audit ]; then
      if ! diff -r "${INT_BACKUP}/audit" /etc/audit >/dev/null 2>&1; then
        echo -e "${RED}[!] PARITY CHECK FAILURE: /etc/audit filesystem mismatch after cleanup!${NC}" >&2
        ROLLBACK_FAILED_STATE=1
      fi
    fi
  fi

  # SAFETY: Never delete recovery material if rollback or parity check failed
  if [ "$ROLLBACK_FAILED_STATE" -eq 0 ]; then
    rm -rf "$INT_BACKUP"
    echo "  [✓] Host cleanup complete: baseline verified, temporary test backup pruned."
  else
    echo -e "${RED}[!] PRESERVING RECOVERY BACKUP AT: ${INT_BACKUP}${NC}" >&2
    echo -e "${RED}[!] Do not remove. Use this directory to manually restore host audit baseline.${NC}" >&2
  fi

  if [ "$ROLLBACK_FAILED_STATE" -ne 0 ]; then
    echo -e "${RED}[!] Host recovery failed during trap execution! Propagating non-zero exit code.${NC}" >&2
    exit 1
  fi
}

handle_signal() {
  local sig="$1"
  echo -e "\n${RED}[!] Caught signal SIG${sig}. Running guaranteed single host cleanup...${NC}" >&2
  cleanup_live_host
  trap - EXIT "$sig"
  kill -s "$sig" "$$"
}
trap cleanup_live_host EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

echo "  - Staging corrupt audit rule directly into ${CANDIDATE_DEST}..."
cp "$CANDIDATE_CORRUPT" "$CANDIDATE_DEST"

# Trigger deployment verification
DEPLOY_FAILED=false
if ! (augenrules --load 2>/dev/null && auditctl -s 2>/dev/null | grep -q "enabled 1"); then
  DEPLOY_FAILED=true
  echo "  [✓] Corrupt rule correctly failed validation. Executing shared production rollback engine (infra/rollback_auditd.sh)..."
  if [ "$ROLLBACK_ALREADY_RUN" = false ]; then
    if [ -f "$PROD_ROLLBACK" ]; then
      if bash "$PROD_ROLLBACK" "$INT_BACKUP" "$CANDIDATE_DEST"; then
        ROLLBACK_ALREADY_RUN=true
        echo "  [✓] Rollback executed successfully."
      else
        echo -e "${RED}[!] FATAL: Production rollback engine failed during recovery!${NC}" >&2
        DEPLOY_FAILED=false
        ROLLBACK_ALREADY_RUN=true
        ROLLBACK_FAILED_STATE=1
      fi
    else
      echo -e "${RED}[!] FATAL: Production rollback engine $PROD_ROLLBACK not found!${NC}" >&2
      ROLLBACK_FAILED_STATE=1
      exit 1
    fi
  fi
else
  # Safety: Even if candidate was unexpectedly accepted, trigger rollback to avoid leaving host modified
  echo "  [!] UNEXPECTED: Corrupt rule was accepted by parser. Triggering forced rollback..." >&2
  if [ "$ROLLBACK_ALREADY_RUN" = false ]; then
    if [ -f "$PROD_ROLLBACK" ]; then
      if bash "$PROD_ROLLBACK" "$INT_BACKUP" "$CANDIDATE_DEST"; then
        ROLLBACK_ALREADY_RUN=true
      else
        echo -e "${RED}[!] FATAL: Production rollback engine failed during unexpected accept recovery!${NC}" >&2
        DEPLOY_FAILED=false
        ROLLBACK_ALREADY_RUN=true
        ROLLBACK_FAILED_STATE=1
      fi
    else
      echo -e "${RED}[!] FATAL: Production rollback engine $PROD_ROLLBACK not found!${NC}" >&2
      ROLLBACK_FAILED_STATE=1
      exit 1
    fi
  fi
fi

# Assert live recovery: Both filesystem configuration and active kernel rules
CURRENT_RULES=$(auditctl -l 2>/dev/null || true)
PRE_RULES=$(cat "${INT_BACKUP}/active_rules_pre.txt" 2>/dev/null || true)
FS_PARITY=true
if [ -d "${INT_BACKUP}/audit" ]; then
  if ! diff -r "${INT_BACKUP}/audit" /etc/audit >/dev/null 2>&1; then
    FS_PARITY=false
  fi
fi

if [ "$DEPLOY_FAILED" = true ] && [ "$CURRENT_RULES" = "$PRE_RULES" ] && [ "$FS_PARITY" = true ] && [ "$ROLLBACK_FAILED_STATE" -eq 0 ]; then
  echo -e "\n${GREEN}[PASS] Live VM Integration: Full Filesystem & Kernel Audit Parity Verified${NC}"
  echo "       Corrupt candidate purged, /etc/audit/ restored bit-for-bit, active kernel policy identical"
  echo -e "\n================================================================"
  echo -e "Live Integration Result: PASSED [ALL PASS]"
  echo -e "================================================================\n"
  exit 0
else
  echo -e "\n${RED}[FAIL] Live VM Integration: Audit Configuration or Kernel Rule Parity Discrepancy${NC}"
  echo "       Discrepancy detected between initial baseline and post-rollback state (FS Parity: $FS_PARITY)"
  exit 1
fi

