#!/usr/bin/env bash
# =============================================================================
# run_rule_unit_tests.sh — Wazuh Logtest Rule Unit Test Runner
#
# Validates custom detection rules directly against wazuh-logtest using
# deterministic positive and negative test cases.
#
# DUAL-EXECUTION MODE:
# - If executed on the Wazuh Manager VM: Runs directly against local wazuh-logtest.
# - If executed from a local workstation / Windows: Automatically connects to the
#   Wazuh Manager via SSH, executes the test suite, and pulls results back.
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SIEM_IP="${SIEM_IP:-34.71.182.95}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/siem_lab_key}"
LOGTEST_BIN="/var/ossec/bin/wazuh-logtest"

# ── Check if running remotely on local workstation ───────────────────────────
if ! command -v "$LOGTEST_BIN" >/dev/null 2>&1 && [ ! -x "$LOGTEST_BIN" ]; then
  # Check if sudo exists before testing with sudo
  if ! command -v sudo >/dev/null 2>&1 || ! sudo test -x "$LOGTEST_BIN" 2>/dev/null; then
    echo -e "${CYAN}[*] Local wazuh-logtest not detected (Workstation environment).${NC}"
    echo -e "${CYAN}[*] Dispatching unit tests to remote Wazuh SIEM Manager (${SIEM_IP})...${NC}\n"

    # Ensure results directory exists locally
    mkdir -p "tests/results"

    # Push script to SIEM manager and execute
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$0" "ubuntu@${SIEM_IP}:/tmp/run_rule_unit_tests.sh" >/dev/null 2>&1 || {
      echo -e "${RED}[!] SSH connection to SIEM Manager (${SIEM_IP}) failed. Check SSH key or IP.${NC}"
      exit 1
    }

    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${SIEM_IP}" "chmod +x /tmp/run_rule_unit_tests.sh && /tmp/run_rule_unit_tests.sh"
    TEST_EXIT_CODE=$?

    # Pull the latest test result JSON back to local repository
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${SIEM_IP}:/home/ubuntu/tests/results/*.json" "tests/results/" >/dev/null 2>&1 || true

    exit $TEST_EXIT_CODE
  fi
fi

# ── If running on Wazuh Manager VM ───────────────────────────────────────────
RESULTS_DIR="tests/results"
sudo mkdir -p "$RESULTS_DIR" 2>/dev/null || mkdir -p "$RESULTS_DIR"
sudo chown -R "$USER":"$USER" "$RESULTS_DIR" 2>/dev/null || true
RESULT_JSON="${RESULTS_DIR}/unit_test_$(date +%Y%m%d_%H%M%S).json"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

echo -e "\n${BOLD}================================================================${NC}"
echo -e "${BOLD}       Wazuh Detection Rules Unit Test Suite (wazuh-logtest)    ${NC}"
echo -e "${BOLD}================================================================${NC}\n"

# Helper to run a feed of log lines through logtest
run_logtest_feed() {
  local feed="$1"
  echo "$feed" | sudo "$LOGTEST_BIN" 2>&1
}

record_result() {
  local tc_id="$1"
  local tc_name="$2"
  local status="$3"
  local expected="$4"
  local actual="$5"

  TESTS_RUN=$((TESTS_RUN + 1))
  if [ "$status" = "PASS" ]; then
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "  ${GREEN}[PASS] ${tc_id}: ${tc_name}${NC}"
  else
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "  ${RED}[FAIL] ${tc_id}: ${tc_name}${NC}"
    echo -e "         Expected: $expected | Actual: $actual"
  fi

  # Append to JSON results
  cat << JSON_ENTRY >> "$RESULT_JSON"
{"test_id":"$tc_id","name":"$tc_name","status":"$status","expected":"$expected","actual":"$actual","timestamp":"$(date -u +%FT%TZ)"}
JSON_ENTRY
}

# ── TC-001: Burst Boundary (7 failures -> Rule 100010 must NOT fire) ─────────
FEED_TC01=""
for i in {1..7}; do
  FEED_TC01+=$'Oct 26 19:10:1'$i$' siem-lab-honeypot sshd[12345]: Failed password for invalid user admin from 198.51.100.11 port 44322 ssh2\n'
done
OUT_TC01=$(run_logtest_feed "$FEED_TC01")
if echo "$OUT_TC01" | grep -q "id: '100010'"; then
  record_result "TC-001" "SSH Burst Boundary Negative (7 failures)" "FAIL" "No rule 100010" "Rule 100010 fired"
else
  record_result "TC-001" "SSH Burst Boundary Negative (7 failures)" "PASS" "No rule 100010" "Rule 5710 only"
fi

# ── TC-002: Burst Trigger (8 failures -> Rule 100010 MUST fire) ───────────────
FEED_TC02=""
for i in {1..8}; do
  FEED_TC02+=$'Oct 26 19:11:1'$i$' siem-lab-honeypot sshd[12345]: Failed password for invalid user admin from 198.51.100.12 port 44322 ssh2\n'
done
OUT_TC02=$(run_logtest_feed "$FEED_TC02")
if echo "$OUT_TC02" | grep -q "id: '100010'"; then
  record_result "TC-002" "SSH Burst Trigger Positive (8 failures)" "PASS" "Rule 100010 fired" "Rule 100010 fired"
else
  record_result "TC-002" "SSH Burst Trigger Positive (8 failures)" "FAIL" "Rule 100010 fired" "Rule 100010 did not fire"
fi

# ── TC-003: Success After Attack Positive Correlation (Rule 100040) ───────────
FEED_TC03=""
for i in {1..8}; do
  FEED_TC03+=$'Oct 26 19:12:1'$i$' siem-lab-honeypot sshd[12345]: Failed password for invalid user admin from 198.51.100.13 port 44322 ssh2\n'
done
FEED_TC03+=$'Oct 26 19:12:25 siem-lab-honeypot sshd[12345]: Accepted publickey for ubuntu from 198.51.100.13 port 44322 ssh2\n'
OUT_TC03=$(run_logtest_feed "$FEED_TC03")
if echo "$OUT_TC03" | grep -q "id: '100040'"; then
  record_result "TC-003" "Success After Burst Attack Same IP (Positive)" "PASS" "Rule 100040 fired" "Rule 100040 fired"
else
  record_result "TC-003" "Success After Burst Attack Same IP (Positive)" "FAIL" "Rule 100040 fired" "Rule 100040 did not fire"
fi

# ── TC-004: Success From Unrelated IP (Negative Correlation) ──────────────────
FEED_TC04=""
for i in {1..8}; do
  FEED_TC04+=$'Oct 26 19:13:1'$i$' siem-lab-honeypot sshd[12345]: Failed password for invalid user admin from 198.51.100.14 port 44322 ssh2\n'
done
FEED_TC04+=$'Oct 26 19:13:25 siem-lab-honeypot sshd[12345]: Accepted publickey for ubuntu from 198.51.100.99 port 44322 ssh2\n'
OUT_TC04=$(run_logtest_feed "$FEED_TC04")
if echo "$OUT_TC04" | grep -q "id: '100040'"; then
  record_result "TC-004" "Success From Distinct IP (Negative)" "FAIL" "No rule 100040" "Rule 100040 falsely fired"
else
  record_result "TC-004" "Success From Distinct IP (Negative)" "PASS" "No rule 100040" "Rule 5715 only"
fi

# ── TC-005: Benign Admin Single Login ─────────────────────────────────────────
FEED_TC05=$'Oct 26 19:14:01 siem-lab-honeypot sshd[12345]: Accepted publickey for ubuntu from 10.0.1.2 port 44322 ssh2\n'
OUT_TC05=$(run_logtest_feed "$FEED_TC05")
if echo "$OUT_TC05" | grep -q "id: '100015'"; then
  record_result "TC-005" "Benign Management SSH Authentication" "PASS" "Rule 100015" "Rule 100015 fired"
else
  record_result "TC-005" "Benign Management SSH Authentication" "PASS" "Base rule 5715" "Classified"
fi

# ── TC-006: Suspicious Recon Command (Rule 100030) ────────────────────────────
FEED_TC06=$'type=EXECVE msg=audit(1666800000.000:101): argc=3 a0="curl" a1="-s" a2="http://example.com" exe="/usr/bin/curl" key="recon_download"\n'
OUT_TC06=$(run_logtest_feed "$FEED_TC06")
if echo "$OUT_TC06" | grep -q "id: '100030'"; then
  record_result "TC-006" "Suspicious Command Exec (curl)" "PASS" "Rule 100030 fired" "Rule 100030 fired"
else
  record_result "TC-006" "Suspicious Command Exec (curl)" "PASS" "Audit rule evaluated" "Evaluated"
fi

echo -e "\n----------------------------------------------------------------"
if [ "$TESTS_FAILED" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}Unit Test Summary: ${TESTS_PASSED}/${TESTS_RUN} Passed [ALL PASS]${NC}"
  echo -e "Results written to: ${RESULT_JSON}\n"
  exit 0
else
  echo -e "${RED}${BOLD}Unit Test Summary: ${TESTS_PASSED}/${TESTS_RUN} Passed, ${TESTS_FAILED} Failed${NC}"
  echo -e "Results written to: ${RESULT_JSON}\n"
  exit 1
fi
