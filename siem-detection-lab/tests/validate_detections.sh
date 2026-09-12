#!/usr/bin/env bash
# =============================================================================
# validate_detections.sh — SIEM Detection Validation Script
# 
# Purpose: Generates controlled test events on the honeypot to verify that 
# custom Wazuh detection rules are firing correctly.
#
# Usage: Run this on the honeypot VM as root. Then check the Wazuh Dashboard.
# =============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Starting SIEM Detection Validation Suite ===${NC}"
echo "Running tests to generate synthetic events..."
echo "Note: Alerts are generated on the Wazuh Manager, not here on the agent."
echo "You will need to verify these in your Wazuh Dashboard after the script finishes."
echo ""

# =============================================================================
# Test Case 01: SSH Brute Force (Rule 100010)
# =============================================================================
echo -e "${CYAN}[TC-01] Testing SSH Brute Force Detection...${NC}"
echo "Injecting 10 failed SSH login events..."

# Inject events into /var/log/auth.log using the auth facility (-p auth.info)
# Without -p auth.info, logger writes to /var/log/syslog which Wazuh's SSH rules don't monitor
for i in {1..10}; do
    logger -p auth.info -t sshd "Failed password for root from 192.168.1.100 port 50000 ssh2"
    sleep 0.5
done
echo -e "${GREEN}✓ TC-01 Events injected. (Check dashboard for Rule 100010)${NC}\n"


# =============================================================================
# Test Case 02: New User Created (Rule 100020)
# =============================================================================
echo -e "${CYAN}[TC-02] Testing New User Creation Detection...${NC}"
echo "Creating and deleting a test user..."

# Create a test user, which triggers auditd, which triggers Wazuh
useradd siem_test_user_99 2>/dev/null || true
sleep 1
userdel siem_test_user_99 2>/dev/null || true
echo -e "${GREEN}✓ TC-02 Events injected. (Check dashboard for Rule 100020)${NC}\n"


# =============================================================================
# Test Case 03: Sudoers Modified (Rule 100021)
# =============================================================================
echo -e "${CYAN}[TC-03] Testing Sudoers Modification Detection...${NC}"
echo "Modifying /etc/sudoers (append and revert)..."

# Safely append a comment and revert it
echo "# SIEM TEST" >> /etc/sudoers
sleep 1
sed -i '/# SIEM TEST/d' /etc/sudoers
echo -e "${GREEN}✓ TC-03 Events injected. (Check dashboard for Rule 100021)${NC}\n"


# =============================================================================
# Test Case 04: Suspicious Commands (Rule 100030)
# =============================================================================
echo -e "${CYAN}[TC-04] Testing Suspicious Command Detection...${NC}"
echo "Executing wget..."

# Run wget to localhost (harmless but triggers auditd)
wget -qO- 127.0.0.1 >/dev/null 2>&1 || true
echo -e "${GREEN}✓ TC-04 Events injected. (Check dashboard for Rule 100030)${NC}\n"


# =============================================================================
# Test Case 05: Login After Brute Force (Rule 100040)
# =============================================================================
echo -e "${CYAN}[TC-05] Testing Login After Brute Force Detection...${NC}"
echo "Injecting 8 failed logins followed by 1 success..."

# Note: We use a different IP to avoid triggering rule 100010 from TC-01 again for the same window
for i in {1..8}; do
    logger -p auth.info -t sshd "Failed password for root from 10.0.0.99 port 50000 ssh2"
    sleep 0.5
done

# Followed by a success
logger -p auth.info -t sshd "Accepted publickey for root from 10.0.0.99 port 50000 ssh2: RSA SHA256:test"
echo -e "${GREEN}✓ TC-05 Events injected. (Check dashboard for Rule 100040)${NC}\n"


# =============================================================================
# Summary
# =============================================================================
echo -e "${YELLOW}=== Event Generation Complete ===${NC}"
echo "All synthetic events have been injected into the honeypot's logs."
echo ""
echo "Next Steps:"
echo "1. Log into your Wazuh Dashboard."
echo "2. Navigate to 'Security events'."
echo "3. Verify the following rules fired in the last 5 minutes:"
echo "   - 100010 (SSH Brute Force Aggregation)"
echo "   - 100020 (New User Created)"
echo "   - 100021 (Sudoers Modified)"
echo "   - 100030 (Suspicious Command Execution)"
echo "   - 100040 (Login After Brute Force)"
