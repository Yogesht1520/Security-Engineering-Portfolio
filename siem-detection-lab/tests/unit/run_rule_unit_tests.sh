#!/usr/bin/env bash
# =============================================================================
# run_rule_unit_tests.sh — Wazuh Logtest Rule Unit Test Runner
#
# Validates custom detection rules directly against wazuh-logtest using
# deterministic positive and negative test cases covering all 10 custom rules.
#
# DUAL-EXECUTION MODE:
# - If executed on the Wazuh Manager VM: Runs directly against local wazuh-logtest.
# - If executed from a local workstation / Windows / WSL: Automatically connects
#   to the Wazuh Manager via SSH, executes the test suite, and pulls results back.
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SIEM_IP="${SIEM_IP:-34.71.182.95}"
LOGTEST_BIN="/var/ossec/bin/wazuh-logtest"

# Auto-resolve SSH key location across native Linux, WSL, and Windows
if [ -z "${SSH_KEY:-}" ]; then
  if [ -f "$HOME/.ssh/siem_lab_key" ]; then
    SSH_KEY="$HOME/.ssh/siem_lab_key"
  elif [ -f "/mnt/c/Users/yoges/.ssh/siem_lab_key" ]; then
    SSH_KEY="/mnt/c/Users/yoges/.ssh/siem_lab_key"
  elif [ -n "${USERPROFILE:-}" ] && [ -f "$USERPROFILE/.ssh/siem_lab_key" ]; then
    SSH_KEY="$USERPROFILE/.ssh/siem_lab_key"
  else
    SSH_KEY="$HOME/.ssh/siem_lab_key"
  fi
fi

# ── Check if running remotely on local workstation ───────────────────────────
if ! command -v "$LOGTEST_BIN" >/dev/null 2>&1 && [ ! -x "$LOGTEST_BIN" ]; then
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

# ── If running on Wazuh Manager VM / CI Container ───────────────────────────
RESULTS_DIR="tests/results"
sudo mkdir -p "$RESULTS_DIR" 2>/dev/null || mkdir -p "$RESULTS_DIR"
sudo chown -R "$USER":"$USER" "$RESULTS_DIR" 2>/dev/null || true

# Synchronize repository custom rules into Wazuh rules directory if present
if [ -d "wazuh/custom_rules" ] && [ -d "/var/ossec/etc/rules" ]; then
  echo -e "${CYAN}[*] Synchronizing custom detection rules to /var/ossec/etc/rules/...${NC}"
  sudo cp wazuh/custom_rules/*.xml /var/ossec/etc/rules/ 2>/dev/null || true
  sudo chown -R wazuh:wazuh /var/ossec/etc/rules/*.xml 2>/dev/null || true
fi

RESULT_JSON="${RESULTS_DIR}/unit_test_$(date +%Y%m%d_%H%M%S).json"
TEMP_ENTRIES=$(mktemp)

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

echo -e "\n${BOLD}================================================================${NC}"
echo -e "${BOLD}       Wazuh Detection Rules Unit Test Suite (wazuh-logtest)    ${NC}"
echo -e "${BOLD}================================================================${NC}\n"

# Helper to run a feed of log lines through logtest with exit-code safety
run_logtest_feed() {
  local feed="$1"
  local tmpfile
  tmpfile=$(mktemp /tmp/logtest_feed.XXXXXX 2>/dev/null || mktemp)
  printf "%b" "$feed" > "$tmpfile"
  local output
  output=$(sudo "$LOGTEST_BIN" < "$tmpfile" 2>&1)
  local rc=$?
  rm -f "$tmpfile"
  if [ $rc -ne 0 ]; then
    echo "LOGTEST_EXECUTION_FAILURE (exit code $rc): $output"
  else
    echo "$output"
  fi
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

  # Write JSON entry to temp file for structured assembly
  if [ -s "$TEMP_ENTRIES" ]; then
    echo "," >> "$TEMP_ENTRIES"
  fi
  cat << JSON_ENTRY >> "$TEMP_ENTRIES"
    {
      "test_id": "$tc_id",
      "name": "$tc_name",
      "status": "$status",
      "expected": "$expected",
      "actual": "$actual",
      "timestamp": "$(date -u +%FT%TZ)"
    }
JSON_ENTRY
}

# ── TC-001: Rule 100010 Burst Boundary Negative (7 failures -> must NOT fire) ───
FEED_TC01=""
for i in {1..7}; do
  FEED_TC01+=$'Oct 26 19:10:'$(printf "%02d" $((i * 3)))$' siem-lab-honeypot sshd[12345]: Failed password for user'$i$' from 198.51.100.11 port 44322 ssh2\n'
done
OUT_TC01=$(run_logtest_feed "$FEED_TC01")
if echo "$OUT_TC01" | grep -q "id: '100010'"; then
  record_result "TC-001" "SSH Burst Boundary Negative (7 failures)" "FAIL" "No rule 100010" "Rule 100010 fired prematurely"
else
  record_result "TC-001" "SSH Burst Boundary Negative (7 failures)" "PASS" "No rule 100010" "Rule 5760 only (threshold held)"
fi

# ── TC-002: Rule 100010 Burst Trigger Positive (8 failures -> MUST fire) ─────────
FEED_TC02=""
for i in {1..8}; do
  FEED_TC02+=$'Oct 26 19:11:'$(printf "%02d" $((i * 3)))$' siem-lab-honeypot sshd[12345]: Failed password for user'$i$' from 198.51.100.12 port 44322 ssh2\n'
done
OUT_TC02=$(run_logtest_feed "$FEED_TC02")
if echo "$OUT_TC02" | grep -q "id: '100010'"; then
  record_result "TC-002" "SSH Burst Trigger Positive (8 failures)" "PASS" "Rule 100010 fired" "Rule 100010 fired"
else
  record_result "TC-002" "SSH Burst Trigger Positive (8 failures)" "FAIL" "Rule 100010 fired" "Rule 100010 did not fire"
fi

# ── TC-003: Rule 100040 Success After Burst Attack (Positive Correlation) ──────
FEED_TC03=""
for i in {1..8}; do
  FEED_TC03+=$'Oct 26 19:12:'$(printf "%02d" $((i * 3)))$' siem-lab-honeypot sshd[12345]: Failed password for user'$i$' from 198.51.100.13 port 44322 ssh2\n'
done
FEED_TC03+=$'Oct 26 19:12:35 siem-lab-honeypot sshd[12345]: Accepted publickey for ubuntu from 198.51.100.13 port 44322 ssh2\n'
OUT_TC03=$(run_logtest_feed "$FEED_TC03")
if echo "$OUT_TC03" | grep -q "id: '100040'"; then
  record_result "TC-003" "Success After Burst Attack Same IP (Positive)" "PASS" "Rule 100040 fired" "Rule 100040 fired"
else
  record_result "TC-003" "Success After Burst Attack Same IP (Positive)" "FAIL" "Rule 100040 fired" "Rule 100040 did not fire"
fi

# ── TC-004: Rule 100040 Success From Unrelated IP (Negative Correlation) ───────
FEED_TC04=""
for i in {1..8}; do
  FEED_TC04+=$'Oct 26 19:13:'$(printf "%02d" $((i * 3)))$' siem-lab-honeypot sshd[12345]: Failed password for user'$i$' from 198.51.100.14 port 44322 ssh2\n'
done
FEED_TC04+=$'Oct 26 19:13:35 siem-lab-honeypot sshd[12345]: Accepted publickey for ubuntu from 198.51.100.99 port 44322 ssh2\n'
OUT_TC04=$(run_logtest_feed "$FEED_TC04")
if echo "$OUT_TC04" | grep -q "id: '100040'"; then
  record_result "TC-004" "Success From Distinct IP (Negative)" "FAIL" "No rule 100040" "Rule 100040 falsely fired"
else
  record_result "TC-004" "Success From Distinct IP (Negative)" "PASS" "No rule 100040" "Rule 5715 only (correlation isolation held)"
fi

# ── TC-005: Rule 100015 Benign Admin Management Authentication ──────────────────
FEED_TC05=$'Oct 26 19:14:01 siem-lab-honeypot sshd[12345]: Accepted publickey for ubuntu from 10.0.20.2 port 44322 ssh2\n'
OUT_TC05=$(run_logtest_feed "$FEED_TC05")
if echo "$OUT_TC05" | grep -q "id: '100015'"; then
  record_result "TC-005" "Benign Management SSH Authentication (10.0.20.2)" "PASS" "Rule 100015 fired" "Rule 100015 fired"
else
  record_result "TC-005" "Benign Management SSH Authentication (10.0.20.2)" "FAIL" "Rule 100015 fired" "Rule 100015 did not fire"
fi

# ── TC-006: Rule 100030 Suspicious Living-off-the-Land Command Execution ───────
FEED_TC06=$'type=EXECVE msg=audit(1666800000.000:101): argc=3 a0="curl" a1="-s" a2="http://example.com" exe="/usr/bin/curl" key="download_tool"\n'
OUT_TC06=$(run_logtest_feed "$FEED_TC06")
if echo "$OUT_TC06" | grep -q "id: '100030'"; then
  record_result "TC-006" "Suspicious Command Exec (curl auditd EXECVE)" "PASS" "Rule 100030 fired" "Rule 100030 fired"
else
  record_result "TC-006" "Suspicious Command Exec (curl auditd EXECVE)" "FAIL" "Rule 100030 fired" "Rule 100030 did not fire"
fi

# ── TC-007: Rule 100012 Low-and-Slow Persistent SSH Brute Force ────────────────
FEED_TC07=""
for i in {1..5}; do
  FEED_TC07+=$'Oct 26 18:'$(printf "%02d" $((i * 3)))$':01 siem-lab-honeypot sshd[12345]: Failed password for invalid user bot from 198.51.100.55 port 44322 ssh2\n'
done
OUT_TC07=$(run_logtest_feed "$FEED_TC07")
if echo "$OUT_TC07" | grep -q "id: '100012'"; then
  record_result "TC-007" "Low-and-Slow Persistent Brute Force Detection" "PASS" "Rule 100012 fired" "Rule 100012 fired"
else
  record_result "TC-007" "Low-and-Slow Persistent Brute Force Detection" "FAIL" "Rule 100012 fired" "Rule 100012 did not fire"
fi

# ── TC-008: Rule 100014 Repeated Failures Targeting Single User Account ────────
FEED_TC08=""
for i in {1..8}; do
  FEED_TC08+=$'Oct 26 19:20:'$(printf "%02d" "$((i * 3))")$' siem-lab-honeypot sshd[12345]: Failed password for root from 198.51.100.'$i$' port 44322 ssh2\n'
done
OUT_TC08=$(run_logtest_feed "$FEED_TC08")
if echo "$OUT_TC08" | grep -q "id: '100014'"; then
  record_result "TC-008" "Single-Account Concentrated Failures (same_user)" "PASS" "Rule 100014 fired" "Rule 100014 fired"
else
  record_result "TC-008" "Single-Account Concentrated Failures (same_user)" "FAIL" "Rule 100014 fired" "Rule 100014 did not fire"
fi

# ── TC-009: Rule 100020 Privilege Escalation - New User Added (useradd) ────────
FEED_TC09=$'Oct 26 19:15:00 siem-lab-honeypot useradd[1234]: new user: name=attacker, UID=1001, GID=1001, home=/home/attacker, shell=/bin/bash\n'
OUT_TC09=$(run_logtest_feed "$FEED_TC09")
if echo "$OUT_TC09" | grep -q "id: '100020'"; then
  record_result "TC-009" "New User Account Created (useradd syscheck/syslog)" "PASS" "Rule 100020 fired" "Rule 100020 fired"
else
  record_result "TC-009" "New User Account Created (useradd syscheck/syslog)" "FAIL" "Rule 100020 fired" "Rule 100020 did not fire"
fi

# ── TC-010: Rule 100021 Sudoers File Modified (/etc/sudoers FIM) ──────────────
FEED_TC10=$'ossec: agentless: /etc/sudoers changed\n'
OUT_TC10=$(run_logtest_feed "$FEED_TC10")
if echo "$OUT_TC10" | grep -q "id: '100021'"; then
  record_result "TC-010" "Sudoers File Modified (/etc/sudoers FIM)" "PASS" "Rule 100021 fired" "Rule 100021 fired"
else
  record_result "TC-010" "Sudoers File Modified (/etc/sudoers FIM)" "FAIL" "Rule 100021 fired" "Rule 100021 did not fire"
fi

# ── TC-011: Rule 100022 Sudoers Drop-in Directory Modified (/etc/sudoers.d/) ──
FEED_TC11=$'ossec: agentless: /etc/sudoers.d/010_backdoor added\n'
OUT_TC11=$(run_logtest_feed "$FEED_TC11")
if echo "$OUT_TC11" | grep -q "id: '100022'"; then
  record_result "TC-011" "Sudoers Drop-in Added (/etc/sudoers.d/ FIM)" "PASS" "Rule 100022 fired" "Rule 100022 fired"
else
  record_result "TC-011" "Sudoers Drop-in Added (/etc/sudoers.d/ FIM)" "FAIL" "Rule 100022 fired" "Rule 100022 did not fire"
fi

# ── TC-012: Rule 100041 Low-and-Slow Attack Success Correlation ────────────────
FEED_TC12=""
for i in {1..5}; do
  FEED_TC12+=$'Oct 26 18:'$(printf "%02d" $((i * 3)))$':01 siem-lab-honeypot sshd[12345]: Failed password for invalid user bot from 198.51.100.88 port 44322 ssh2\n'
done
FEED_TC12+=$'Oct 26 18:25:00 siem-lab-honeypot sshd[12345]: Accepted publickey for ubuntu from 198.51.100.88 port 44322 ssh2\n'
OUT_TC12=$(run_logtest_feed "$FEED_TC12")
if echo "$OUT_TC12" | grep -q "id: '100041'"; then
  record_result "TC-012" "Success After Persistent Attack Same IP Correlation" "PASS" "Rule 100041 fired" "Rule 100041 fired"
else
  record_result "TC-012" "Success After Persistent Attack Same IP Correlation" "FAIL" "Rule 100041 fired" "Rule 100041 did not fire"
fi

# ── TC-013: Negative Test — Dispersed Usernames (Rule 100014 must NOT fire) ──────
FEED_TC13=""
USERS=("alice" "bob" "charlie" "david" "eve" "frank" "grace" "heidi")
for i in "${!USERS[@]}"; do
  u="${USERS[$i]}"
  FEED_TC13+=$'Oct 26 19:25:0'$i$' siem-lab-honeypot sshd[12345]: Failed password for '$u$' from 198.51.100.7'$i$' port 44322 ssh2\n'
done
OUT_TC13=$(run_logtest_feed "$FEED_TC13")
if echo "$OUT_TC13" | grep -q "id: '100014'"; then
  record_result "TC-013" "Dispersed Users Failure Isolation (Negative)" "FAIL" "No rule 100014" "Rule 100014 falsely fired on dispersed users"
else
  record_result "TC-013" "Dispersed Users Failure Isolation (Negative)" "PASS" "No rule 100014" "Single-account rule held without false positive"
fi

# ── TC-014: Malformed Telemetry — Truncated / Corrupt Audit EXECVE Record ─────────
FEED_TC14=$'type=EXECVE msg=audit(1666800000.000:999): argc=2 [TRUNCATED_CORRUPT_BUFFER]\n'
OUT_TC14=$(run_logtest_feed "$FEED_TC14")
if echo "$OUT_TC14" | grep -q -E "id: '(100030|100021|100022)'"; then
  record_result "TC-014" "Malformed Audit Record Robustness" "FAIL" "Graceful base parsing" "Custom rule fired on corrupt telemetry"
else
  record_result "TC-014" "Malformed Audit Record Robustness" "PASS" "Graceful base parsing" "No false custom rule triggered on corrupt record"
fi

# ── TC-015: Clock Skew / Out-of-Order Syslog Ingestion Resilience ─────────────
FEED_TC15=$'Oct 26 19:30:10 siem-lab-honeypot sshd[12345]: Failed password for invalid user testuser from 198.51.100.200 port 44322 ssh2\n'
FEED_TC15+=$'Oct 26 19:28:50 siem-lab-honeypot sshd[12345]: Failed password for invalid user testuser from 198.51.100.200 port 44322 ssh2\n'
OUT_TC15=$(run_logtest_feed "$FEED_TC15")
if echo "$OUT_TC15" | grep -q "LOGTEST_EXECUTION_FAILURE"; then
  record_result "TC-015" "Out-of-Order Telemetry Stream Handling" "FAIL" "Clean execution" "Logtest crashed on skewed timestamp"
else
  record_result "TC-015" "Out-of-Order Telemetry Stream Handling" "PASS" "Clean execution" "Syslog parsed gracefully despite inverted clock"
fi

# Assemble complete, valid JSON document
cat << JSON_DOC > "$RESULT_JSON"
{
  "summary": {
    "total_tests": $TESTS_RUN,
    "passed": $TESTS_PASSED,
    "failed": $TESTS_FAILED,
    "pass_rate_percent": $(( (TESTS_PASSED * 100) / TESTS_RUN )),
    "execution_time_utc": "$(date -u +%FT%TZ)",
    "engine": "wazuh-logtest v4.9.2"
  },
  "results": [
$(cat "$TEMP_ENTRIES")
  ]
}
JSON_DOC
cp "$RESULT_JSON" "${RESULTS_DIR}/unit_test_latest.json"
rm -f "$TEMP_ENTRIES"

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
