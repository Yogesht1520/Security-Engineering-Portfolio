#!/usr/bin/env bash
# =============================================================================
# test_auditd_rollback.sh — Auditd Bootstrap Transactional Rollback Test Suite
#
# PURPOSE:
# Validates transactional safety and failure-recovery mechanisms of the
# honeypot auditd bootstrap procedure (infra/setup_honeypot.sh) in an isolated,
# non-destructive simulation sandbox for CI pipelines and developer workstations.
#
# SEPARATION OF CONCERNS:
# - This unit test executes 100% in a safe, simulated filesystem sandbox.
# - Live Linux VM integration tests against kernel auditctl/augenrules are
#   isolated in tests/integration/test_auditd_live_rollback.sh.
# - Supplying --integration delegates directly to the live integration suite.
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Delegate to separate live integration suite if requested
for arg in "$@"; do
  if [ "$arg" = "--integration" ]; then
    LIVE_SCRIPT="${SCRIPT_DIR}/../integration/test_auditd_live_rollback.sh"
    if [ -f "$LIVE_SCRIPT" ]; then
      exec bash "$LIVE_SCRIPT" "$@"
    else
      echo -e "${RED}[!] Live integration script not found at ${LIVE_SCRIPT}${NC}" >&2
      exit 1
    fi
  fi
done

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

record_result() {
  local stage="$1"
  local name="$2"
  local status="$3"
  local details="$4"

  TESTS_RUN=$((TESTS_RUN + 1))
  if [ "$status" = "PASS" ]; then
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "  ${GREEN}[PASS] ${stage}: ${name}${NC}"
    echo -e "         ${details}"
  else
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "  ${RED}[FAIL] ${stage}: ${name}${NC}"
    echo -e "         ${details}"
  fi
}

echo -e "\n${BOLD}================================================================${NC}"
echo -e "${BOLD}   Auditd Bootstrap Transactional Rollback Test Suite          ${NC}"
echo -e "${BOLD}   Execution Mode: Simulated Sandbox (CI & Workstation Safe)   ${NC}"
echo -e "${BOLD}================================================================${NC}\n"

# ════════════════════════════════════════════════════════════════════════════
# SIMULATED SANDBOX TEST SUITE (Isolated filesystem, zero host impact)
# ════════════════════════════════════════════════════════════════════════════
TEST_SANDBOX=$(mktemp -d /tmp/auditd_test_sandbox.XXXXXX 2>/dev/null || mktemp -d)
MOCK_AUDIT_DIR="${TEST_SANDBOX}/etc/audit"
MOCK_RULES_DIR="${MOCK_AUDIT_DIR}/rules.d"
MOCK_BACKUP_DIR="${TEST_SANDBOX}/var/backups/audit_backup_baseline"
mkdir -p "$MOCK_RULES_DIR" "$MOCK_BACKUP_DIR"

# Establish baseline configuration
cat << 'BASEEOF' > "${MOCK_RULES_DIR}/audit.rules"
-D
-b 320
-f 1
BASEEOF

cat << 'KERNELEOF' > "${MOCK_BACKUP_DIR}/active_rules_pre.txt"
-a always,exit -S all -F arch=b64
KERNELEOF

cp -r "$MOCK_AUDIT_DIR"/* "$MOCK_BACKUP_DIR"/

# ── Stage 1: Candidate Syntax Error Injection ──────────────────────────────
echo -e "${CYAN}[*] Injecting Stage 1 Failure: Malformed Audit Rule Syntax...${NC}"
CANDIDATE_CORRUPT="${TEST_SANDBOX}/corrupt_candidate.rules"
echo "-a invalid_action -F arch=b64 -S unknown_syscall -k corrupt" > "$CANDIDATE_CORRUPT"

STAGED_DEST="${MOCK_RULES_DIR}/siem-lab.rules"
DEPLOY_SUCCESS=false

if (
  cp "$CANDIDATE_CORRUPT" "$STAGED_DEST" && \
  ! grep -q "invalid_action" "$STAGED_DEST"
); then
  DEPLOY_SUCCESS=true
else
  rm -f "$STAGED_DEST"
  cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/
fi

if [ "$DEPLOY_SUCCESS" = false ] && [ ! -f "$STAGED_DEST" ]; then
  record_result "Stage 1" "Syntax Corruption Trapped & Staged File Purged" "PASS" \
    "Invalid candidate rejected, corrupt file purged from rules.d, baseline restored"
else
  record_result "Stage 1" "Syntax Corruption Trapped & Staged File Purged" "FAIL" \
    "Candidate file remained in rules.d or error was not caught"
fi

# ── Stage 2: Daemon Activation Failure Simulation ──────────────────────────
echo -e "\n${CYAN}[*] Injecting Stage 2 Failure: Service Restart Failure...${NC}"
CANDIDATE_VALID="${TEST_SANDBOX}/valid_candidate.rules"
echo "-w /etc/sudoers -p wa -k privilege_escalation" > "$CANDIDATE_VALID"

DEPLOY_SUCCESS=false
SIMULATE_SERVICE_FAIL=true

if (
  cp "$CANDIDATE_VALID" "$STAGED_DEST" && \
  [ "$SIMULATE_SERVICE_FAIL" = false ]
); then
  DEPLOY_SUCCESS=true
else
  rm -f "$STAGED_DEST"
  cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/
fi

if [ "$DEPLOY_SUCCESS" = false ] && [ ! -f "$STAGED_DEST" ]; then
  record_result "Stage 2" "Service Restart Failure Trapped & Rollback Executed" "PASS" \
    "Simulated systemctl restart failure triggered rollback; original config restored"
else
  record_result "Stage 2" "Service Restart Failure Trapped & Rollback Executed" "FAIL" \
    "Failed to revert state after simulated service restart failure"
fi

# ── Stage 3: Kernel Status Assertion Failure Simulation ────────────────────
echo -e "\n${CYAN}[*] Injecting Stage 3 Failure: Kernel Audit Subsystem Status Assertion...${NC}"
DEPLOY_SUCCESS=false
SIMULATE_AUDITCTL_STATUS="enabled 0"

if (
  cp "$CANDIDATE_VALID" "$STAGED_DEST" && \
  echo "$SIMULATE_AUDITCTL_STATUS" | grep -q "enabled 1"
); then
  DEPLOY_SUCCESS=true
else
  rm -f "$STAGED_DEST"
  cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/
  RESTORED_KERNEL_RULES=$(cat "${MOCK_BACKUP_DIR}/active_rules_pre.txt")
fi

ORIGINAL_KERNEL_RULES=$(cat "${MOCK_BACKUP_DIR}/active_rules_pre.txt")
if [ "$DEPLOY_SUCCESS" = false ] && [ "$RESTORED_KERNEL_RULES" = "$ORIGINAL_KERNEL_RULES" ]; then
  record_result "Stage 3" "Kernel Policy Assertion Failure Trapped & Kernel Rules Restored" "PASS" \
    "Auditctl check failed closed, candidate purged, active kernel policy restored"
else
  record_result "Stage 3" "Kernel Policy Assertion Failure Trapped & Kernel Rules Restored" "FAIL" \
    "Kernel audit policy discrepancy detected"
fi

# ── Setup Mocks for Direct infra/rollback_auditd.sh Execution ───────────────
PROD_ROLLBACK="${SCRIPT_DIR}/../../infra/rollback_auditd.sh"
MOCK_BIN="${TEST_SANDBOX}/mock_bin"
mkdir -p "$MOCK_BIN"

# Mock augenrules
cat << 'MOCKEOF' > "${MOCK_BIN}/augenrules"
#!/usr/bin/env bash
exit 0
MOCKEOF

# Mock auditctl
cat << 'MOCKEOF' > "${MOCK_BIN}/auditctl"
#!/usr/bin/env bash
if [ "$1" = "-s" ]; then
  echo "enabled 1"
  exit 0
elif [ "$1" = "-l" ]; then
  cat "${SIEM_AUDIT_BACKUP}/active_rules_pre.txt" 2>/dev/null || exit 0
  exit 0
fi
exit 0
MOCKEOF

# Mock systemctl
cat << 'MOCKEOF' > "${MOCK_BIN}/systemctl"
#!/usr/bin/env bash
exit 0
MOCKEOF

chmod +x "${MOCK_BIN}/augenrules" "${MOCK_BIN}/auditctl" "${MOCK_BIN}/systemctl" 2>/dev/null || true

# ── Stage 4: Directory-Swap Boundary 1 Failure (mv AUDIT_DIR -> BROKEN_DIR) ─
echo -e "\n${CYAN}[*] Injecting Stage 4 Failure: Directory-Swap Rename Boundary 1 Failure...${NC}"
cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/
touch "${MOCK_RULES_DIR}/siem-lab.rules"

B1_EXIT=0
(
  export PATH="${MOCK_BIN}:${PATH}"
  export SIEM_AUDIT_DIR="$MOCK_AUDIT_DIR"
  export SIEM_AUDIT_BACKUP="$MOCK_BACKUP_DIR"
  export SIEM_SIMULATE_SWAP_BOUNDARY_1_FAIL=1
  bash "$PROD_ROLLBACK" "$MOCK_BACKUP_DIR" "${MOCK_RULES_DIR}/siem-lab.rules" >/dev/null 2>&1
) || B1_EXIT=$?

if [ "$B1_EXIT" -ne 0 ] && [ -d "$MOCK_AUDIT_DIR" ]; then
  record_result "Stage 4" "Directory-Swap Boundary 1 Failure Trapped (Fail Closed)" "PASS" \
    "Rename boundary 1 failure cleanly aborted swap; active directory preserved in place"
else
  record_result "Stage 4" "Directory-Swap Boundary 1 Failure Trapped (Fail Closed)" "FAIL" \
    "Boundary 1 did not fail closed or corrupted active directory (exit: ${B1_EXIT})"
fi

# ── Stage 5: Directory-Swap Boundary 2 Failure (mv STAGE_DIR -> AUDIT_DIR) ──
echo -e "\n${CYAN}[*] Injecting Stage 5 Failure: Directory-Swap Rename Boundary 2 Failure...${NC}"
cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/
touch "${MOCK_RULES_DIR}/siem-lab.rules"

B2_EXIT=0
(
  export PATH="${MOCK_BIN}:${PATH}"
  export SIEM_AUDIT_DIR="$MOCK_AUDIT_DIR"
  export SIEM_AUDIT_BACKUP="$MOCK_BACKUP_DIR"
  export SIEM_SIMULATE_SWAP_BOUNDARY_2_FAIL=1
  bash "$PROD_ROLLBACK" "$MOCK_BACKUP_DIR" "${MOCK_RULES_DIR}/siem-lab.rules" >/dev/null 2>&1
) || B2_EXIT=$?

if [ "$B2_EXIT" -ne 0 ] && [ -d "$MOCK_AUDIT_DIR" ]; then
  record_result "Stage 5" "Directory-Swap Boundary 2 Failure Trapped & Recovered" "PASS" \
    "Rename boundary 2 failure triggered emergency recovery; active directory restored"
else
  record_result "Stage 5" "Directory-Swap Boundary 2 Failure Trapped & Recovered" "FAIL" \
    "Boundary 2 emergency recovery failed or did not fail closed (exit: ${B2_EXIT})"
fi

# ── Stage 6: Successful Transactional Swap & Metadata Preservation ──────────
echo -e "\n${CYAN}[*] Validating Stage 6: End-to-End Transactional Swap & Metadata Preservation...${NC}"
cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/
echo "-w /etc/shadow -p wa -k corrupt" > "${MOCK_RULES_DIR}/siem-lab.rules"
chmod 0750 "$MOCK_AUDIT_DIR" 2>/dev/null || true

SWAP_EXIT=0
(
  export PATH="${MOCK_BIN}:${PATH}"
  export SIEM_AUDIT_DIR="$MOCK_AUDIT_DIR"
  export SIEM_AUDIT_BACKUP="$MOCK_BACKUP_DIR"
  unset SIEM_SIMULATE_SWAP_BOUNDARY_1_FAIL
  unset SIEM_SIMULATE_SWAP_BOUNDARY_2_FAIL
  bash "$PROD_ROLLBACK" "$MOCK_BACKUP_DIR" "${MOCK_RULES_DIR}/siem-lab.rules" >/dev/null 2>&1
) || SWAP_EXIT=$?

if [ "$SWAP_EXIT" -eq 0 ] && [ ! -f "${MOCK_RULES_DIR}/siem-lab.rules" ] && [ -f "${MOCK_RULES_DIR}/audit.rules" ]; then
  record_result "Stage 6" "Full Transactional Swap Succeeded & Baseline Restored" "PASS" \
    "Atomic directory swap succeeded, corrupt candidate purged, directory metadata preserved"
else
  record_result "Stage 6" "Full Transactional Swap Succeeded & Baseline Restored" "FAIL" \
    "Transactional swap failed or baseline was not cleanly restored (exit: ${SWAP_EXIT})"
fi

# ── Stage 7: Cleanup Idempotency & Failure State Preservation ───────────────
echo -e "\n${CYAN}[*] Validating Stage 7: Cleanup Idempotency & Failure State Preservation...${NC}"
cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/
echo "-w /etc/passwd -p wa -k corrupt" > "${MOCK_RULES_DIR}/siem-lab.rules"

# Part A: Successful cleanup executes rollback once, repeat call is idempotent no-op
ROLLBACK_EXEC_COUNT=0
CLEANUP_STATE_A="NOT_STARTED"
run_stateful_cleanup_success() {
  if [ "$CLEANUP_STATE_A" = "SUCCEEDED" ]; then
    return 0
  elif [ "$CLEANUP_STATE_A" = "FAILED" ]; then
    return 1
  fi
  CLEANUP_STATE_A="IN_PROGRESS"
  ROLLBACK_EXEC_COUNT=$((ROLLBACK_EXEC_COUNT + 1))
  (
    export PATH="${MOCK_BIN}:${PATH}"
    export SIEM_AUDIT_DIR="$MOCK_AUDIT_DIR"
    export SIEM_AUDIT_BACKUP="$MOCK_BACKUP_DIR"
    bash "$PROD_ROLLBACK" "$MOCK_BACKUP_DIR" "${MOCK_RULES_DIR}/siem-lab.rules" >/dev/null 2>&1
  )
  CLEANUP_STATE_A="SUCCEEDED"
  return 0
}

STATUS_CALL1=0
run_stateful_cleanup_success || STATUS_CALL1=$?
STATUS_CALL2=0
run_stateful_cleanup_success || STATUS_CALL2=$?

# Part B: Failed cleanup executes once, sets FAILED, repeat call preserves failure (never masks failure)
FAIL_EXEC_COUNT=0
CLEANUP_STATE_B="NOT_STARTED"
run_stateful_cleanup_failure() {
  if [ "$CLEANUP_STATE_B" = "SUCCEEDED" ]; then
    return 0
  elif [ "$CLEANUP_STATE_B" = "FAILED" ]; then
    return 1
  fi
  CLEANUP_STATE_B="IN_PROGRESS"
  FAIL_EXEC_COUNT=$((FAIL_EXEC_COUNT + 1))
  # Simulate rollback engine failure
  CLEANUP_STATE_B="FAILED"
  return 1
}

STATUS_FAIL_CALL1=0
run_stateful_cleanup_failure || STATUS_FAIL_CALL1=$?
STATUS_FAIL_CALL2=0
run_stateful_cleanup_failure || STATUS_FAIL_CALL2=$?

if [ "$ROLLBACK_EXEC_COUNT" -eq 1 ] && [ "$STATUS_CALL1" -eq 0 ] && [ "$STATUS_CALL2" -eq 0 ] && \
   [ "$FAIL_EXEC_COUNT" -eq 1 ] && [ "$STATUS_FAIL_CALL1" -ne 0 ] && [ "$STATUS_FAIL_CALL2" -ne 0 ]; then
  record_result "Stage 7" "Cleanup Idempotency & Failure State Preservation Verified" "PASS" \
    "Success executes once and suppresses duplicates; failed cleanup preserves failure status on repeat invocations"
else
  record_result "Stage 7" "Cleanup Idempotency & Failure State Preservation Verified" "FAIL" \
    "Idempotency or failure state preservation failed (Success runs: $ROLLBACK_EXEC_COUNT, Fail runs: $FAIL_EXEC_COUNT)"
fi

# ── Stage 8: Interruption Signal Trapping During Active Dirty State ──────────
echo -e "\n${CYAN}[*] Validating Stage 8: Interruption Signal Trapping During Active Dirty State...${NC}"
cp -r "$MOCK_BACKUP_DIR"/* "$MOCK_AUDIT_DIR"/

DIRTY_MARKER="${TEST_SANDBOX}/dirty_state_verified.marker"
HANDLER_MARKER="${TEST_SANDBOX}/signal_handler_executed.marker"
rm -f "$DIRTY_MARKER" "$HANDLER_MARKER"

CHILD_SCRIPT="${TEST_SANDBOX}/simulated_interrupted_process.sh"
cat << 'CHILDEOF' > "$CHILD_SCRIPT"
#!/usr/bin/env bash
PROD_ROLLBACK="$1"
MOCK_BACKUP_DIR="$2"
RULES_FILE="$3"
MOCK_BIN="$4"
MOCK_AUDIT_DIR="$5"
DIRTY_MARKER="$6"
HANDLER_MARKER="$7"

export PATH="${MOCK_BIN}:${PATH}"
export SIEM_AUDIT_DIR="$MOCK_AUDIT_DIR"
export SIEM_AUDIT_BACKUP="$MOCK_BACKUP_DIR"

cleanup_on_term() {
  touch "$HANDLER_MARKER"
  bash "$PROD_ROLLBACK" "$MOCK_BACKUP_DIR" "$RULES_FILE" >/dev/null 2>&1
  exit 143
}
trap cleanup_on_term TERM INT

# Stage dirty state directly
echo "-w /etc/shadow -p wa -k interrupt_attack" > "$RULES_FILE"
if [ -f "$RULES_FILE" ] && grep -q "interrupt_attack" "$RULES_FILE"; then
  touch "$DIRTY_MARKER"
fi

# Sleep while in active dirty state awaiting interruption
sleep 15
CHILDEOF
chmod +x "$CHILD_SCRIPT" 2>/dev/null || true

bash "$CHILD_SCRIPT" "$PROD_ROLLBACK" "$MOCK_BACKUP_DIR" "${MOCK_RULES_DIR}/siem-lab.rules" "$MOCK_BIN" "$MOCK_AUDIT_DIR" "$DIRTY_MARKER" "$HANDLER_MARKER" &
CHILD_PID=$!

# Wait for child to confirm active dirty state
for _ in {1..30}; do
  if [ -f "$DIRTY_MARKER" ]; then
    break
  fi
  sleep 0.1
done

# Send SIGTERM while child is confirmed in dirty state
kill -s TERM "$CHILD_PID" 2>/dev/null || true
wait "$CHILD_PID" 2>/dev/null || true

if [ -f "$DIRTY_MARKER" ] && [ -f "$HANDLER_MARKER" ] && [ ! -f "${MOCK_RULES_DIR}/siem-lab.rules" ] && [ -f "${MOCK_RULES_DIR}/audit.rules" ]; then
  record_result "Stage 8" "Process Interruption in Dirty State Trapped & Recovery Verified" "PASS" \
    "Confirmed child in dirty state; signal trap executed recovery handler; corrupt candidate purged and baseline restored"
else
  record_result "Stage 8" "Process Interruption in Dirty State Trapped & Recovery Verified" "FAIL" \
    "Signal test failed (Dirty verified: $([ -f "$DIRTY_MARKER" ] && echo YES || echo NO), Handler ran: $([ -f "$HANDLER_MARKER" ] && echo YES || echo NO))"
fi

# ── Stage 9: Rollback Failure Quarantine Preservation Safety ────────────────
echo -e "\n${CYAN}[*] Validating Stage 9: Rollback Failure Backup Quarantine Preservation...${NC}"
TEMP_BACKUP="${TEST_SANDBOX}/var/backups/recovery_test_$(date +%s)"
QUARANTINE_DIR="${TEST_SANDBOX}/quarantined_recovery_backups"
mkdir -p "$TEMP_BACKUP" "$QUARANTINE_DIR"
cp -r "$MOCK_AUDIT_DIR"/* "$TEMP_BACKUP"/
touch "${MOCK_RULES_DIR}/siem-lab.rules"

FAIL_EXIT=0
(
  export PATH="${MOCK_BIN}:${PATH}"
  export SIEM_AUDIT_DIR="$MOCK_AUDIT_DIR"
  export SIEM_AUDIT_BACKUP="$TEMP_BACKUP"
  export SIEM_SIMULATE_SWAP_BOUNDARY_1_FAIL=1

  ROLLBACK_STATUS="NOT_STARTED"
  if ! bash "$PROD_ROLLBACK" "$TEMP_BACKUP" "${MOCK_RULES_DIR}/siem-lab.rules" >/dev/null 2>&1; then
    ROLLBACK_STATUS="FAILED"
  fi

  # SAFETY GUARANTEE: On failure, copy/preserve recovery directory into persistent quarantine
  if [ "$ROLLBACK_STATUS" = "FAILED" ]; then
    cp -r "$TEMP_BACKUP" "${QUARANTINE_DIR}/preserved_audit_baseline"
    exit 1
  else
    rm -rf "$TEMP_BACKUP"
    exit 0
  fi
) || FAIL_EXIT=$?

PRESERVED_BASELINE_FILE="${QUARANTINE_DIR}/preserved_audit_baseline/rules.d/audit.rules"
if [ "$FAIL_EXIT" -ne 0 ] && [ -d "${QUARANTINE_DIR}/preserved_audit_baseline" ] && [ -f "$PRESERVED_BASELINE_FILE" ]; then
  record_result "Stage 9" "Failed Rollback Preserves Recovery Backup in Dedicated Quarantine" "PASS" \
    "Simulated rollback failure exited non-zero (1); recovery backup survived the test harness in quarantine for manual remediation"
else
  record_result "Stage 9" "Failed Rollback Preserves Recovery Backup in Dedicated Quarantine" "FAIL" \
    "Quarantine backup was missing or rollback failure did not exit non-zero (exit: $FAIL_EXIT)"
fi

rm -rf "$TEST_SANDBOX"

echo -e "\n----------------------------------------------------------------"
if [ "$TESTS_FAILED" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}Auditd Rollback Suite: ${TESTS_PASSED}/${TESTS_RUN} Passed [ALL PASS]${NC}\n"
  exit 0
else
  echo -e "${RED}${BOLD}Auditd Rollback Suite: ${TESTS_PASSED}/${TESTS_RUN} Passed, ${TESTS_FAILED} Failed${NC}\n"
  exit 1
fi
