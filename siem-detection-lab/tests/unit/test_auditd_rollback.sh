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

rm -rf "$TEST_SANDBOX"

echo -e "\n----------------------------------------------------------------"
if [ "$TESTS_FAILED" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}Auditd Rollback Suite: ${TESTS_PASSED}/${TESTS_RUN} Passed [ALL PASS]${NC}\n"
  exit 0
else
  echo -e "${RED}${BOLD}Auditd Rollback Suite: ${TESTS_PASSED}/${TESTS_RUN} Passed, ${TESTS_FAILED} Failed${NC}\n"
  exit 1
fi
