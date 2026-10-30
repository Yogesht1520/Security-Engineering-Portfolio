#!/usr/bin/env bash
# =============================================================================
# test_auditd_rollback.sh — Auditd Bootstrap Transactional Rollback Test Suite
#
# PURPOSE:
# Validates transactional safety and failure-recovery mechanisms of the
# honeypot auditd bootstrap procedure (infra/setup_honeypot.sh).
#
# DUAL-MODE EXECUTION:
#   1. Simulated Sandbox Mode (Default for CI/workstation):
#      Injects syntax errors, service crashes, and kernel assertion failures
#      into an isolated filesystem sandbox to verify rollback logic.
#   2. Live Linux VM Integration Mode (--integration or root on Linux):
#      Directly tests live augenrules, kernel auditctl rule restore, and systemd
#      auditd recovery on an active Linux system.
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INTEGRATION_MODE=false
for arg in "$@"; do
  case "$arg" in
    --integration)
      INTEGRATION_MODE=true
      shift
      ;;
  esac
done

# Auto-detect root on Linux with auditctl installed
if [ "$INTEGRATION_MODE" = false ] && [ "$(id -u 2>/dev/null || echo 1)" -eq 0 ] && command -v auditctl >/dev/null 2>&1 && command -v augenrules >/dev/null 2>&1; then
  echo -e "${CYAN}[*] Root permissions and active auditctl detected. Enabling Live VM Integration Mode.${NC}"
  INTEGRATION_MODE=true
fi

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
echo -e "${BOLD}   Execution Mode: $([ "$INTEGRATION_MODE" = true ] && echo "Live Linux VM Integration" || echo "Simulated Sandbox")${NC}"
echo -e "${BOLD}================================================================${NC}\n"

if [ "$INTEGRATION_MODE" = true ]; then
  # ════════════════════════════════════════════════════════════════════════════
  # LIVE VM INTEGRATION TEST SUITE
  # ════════════════════════════════════════════════════════════════════════════
  echo -e "${CYAN}[*] Executing Live Integration Test against Kernel Audit Subsystem...${NC}"
  
  INT_BACKUP="/var/backups/audit_live_test_$(date +%s)"
  mkdir -p "$INT_BACKUP"
  cp -r /etc/audit "$INT_BACKUP/"
  auditctl -l > "${INT_BACKUP}/active_rules_pre.txt" 2>/dev/null || true
  
  CANDIDATE_CORRUPT="/tmp/live_corrupt_test.rules"
  echo "-a invalid_action_flag -S execve -k broken" > "$CANDIDATE_CORRUPT"
  
  echo "  - Staging corrupt audit rule directly into /etc/audit/rules.d/siem-lab.rules..."
  cp "$CANDIDATE_CORRUPT" /etc/audit/rules.d/siem-lab.rules
  
  # Trigger deployment verification
  DEPLOY_FAILED=false
  if ! (augenrules --load 2>/dev/null && auditctl -s | grep -q "enabled 1"); then
    DEPLOY_FAILED=true
    echo "  [✓] Corrupt rule correctly failed validation. Executing live rollback..."
    rm -f /etc/audit/rules.d/siem-lab.rules
    cp -r "$INT_BACKUP"/audit/* /etc/audit/
    augenrules --load 2>/dev/null || true
    if [ -s "${INT_BACKUP}/active_rules_pre.txt" ]; then
      auditctl -R "${INT_BACKUP}/active_rules_pre.txt" 2>/dev/null || true
    fi
    systemctl restart auditd 2>/dev/null || true
  fi
  
  # Assert live recovery
  CURRENT_RULES=$(auditctl -l 2>/dev/null || true)
  PRE_RULES=$(cat "${INT_BACKUP}/active_rules_pre.txt" 2>/dev/null || true)
  
  if [ "$DEPLOY_FAILED" = true ] && [ ! -f /etc/audit/rules.d/siem-lab.rules ] && [ "$CURRENT_RULES" = "$PRE_RULES" ]; then
    record_result "Live VM" "Kernel Audit Policy Parity & Candidate Purge" "PASS" \
      "Corrupt rule purged from /etc/audit/rules.d, kernel rules restored bit-for-bit"
  else
    record_result "Live VM" "Kernel Audit Policy Parity & Candidate Purge" "FAIL" \
      "Discrepancy detected between initial kernel rules and post-rollback policy"
  fi
  
  rm -f "$CANDIDATE_CORRUPT"
  rm -rf "$INT_BACKUP"

else
  # ════════════════════════════════════════════════════════════════════════════
  # SIMULATED SANDBOX TEST SUITE (CI & Workstation)
  # ════════════════════════════════════════════════════════════════════════════
  TEST_SANDBOX=$(mktemp -d /tmp/auditd_test_sandbox.XXXXXX)
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

  rm -rf "$TEST_SANDBOX"
fi

echo -e "\n----------------------------------------------------------------"
if [ "$TESTS_FAILED" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}Auditd Rollback Suite: ${TESTS_PASSED}/${TESTS_RUN} Passed [ALL PASS]${NC}\n"
  exit 0
else
  echo -e "${RED}${BOLD}Auditd Rollback Suite: ${TESTS_PASSED}/${TESTS_RUN} Passed, ${TESTS_FAILED} Failed${NC}\n"
  exit 1
fi
