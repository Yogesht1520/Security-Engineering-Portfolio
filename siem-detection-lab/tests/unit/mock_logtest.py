#!/usr/bin/env python3
"""
mock_logtest.py — Autonomous CI Mock Engine for wazuh-logtest

Simulates wazuh-logtest rule evaluation in continuous integration environments
where a full Wazuh SIEM manager cluster is not running. Evaluates rules
100010 through 100041 based on the deterministic criteria in wazuh/custom_rules/.
"""

import sys
import re

def evaluate(feed: str) -> str:
    lines = [line.strip() for line in feed.strip().splitlines() if line.strip()]
    if not lines:
        return "** Phase 3: Completed filtering (rules).\n       id: '0'"

    output = []
    
    # Track state across multi-line feeds (for composite / frequency rules)
    failed_sshd_events = []
    accepted_sshd_events = []
    
    for line in lines:
        # Check corrupt / truncated buffer
        if "[TRUNCATED_CORRUPT_BUFFER]" in line:
            output.append("** Phase 2: Completed decoding.\n** Phase 3: Completed filtering (rules).\n       id: '5501'")
            continue
            
        # Benign management SSH rule 100015
        if "Accepted publickey for" in line and "from 10.0.20.2" in line:
            output.append("** Phase 3: Completed filtering (rules).\n       id: '100015'\n       level: '3'\n       description: 'sshd: Benign administrative authentication from SIEM'")
            continue

        # Suspicious living-off-the-land command execution rule 100030
        if 'type=EXECVE' in line:
            if 'key="download_tool"' in line or 'key="network_tool"' in line or 'exe="/usr/bin/curl"' in line or 'exe="/usr/bin/wget"' in line:
                output.append("** Phase 3: Completed filtering (rules).\n       id: '100030'\n       level: '12'\n       description: 'Suspicious post-exploitation reconnaissance/exfiltration tool executed'")
                continue

        # New user account created rule 100020
        if "useradd[" in line and "new user:" in line:
            output.append("** Phase 3: Completed filtering (rules).\n       id: '100020'\n       level: '8'\n       description: 'System administration: New user account created'")
            continue

        # Sudoers file modified rule 100021
        if "ossec: agentless: /etc/sudoers changed" in line:
            output.append("** Phase 3: Completed filtering (rules).\n       id: '100021'\n       level: '12'\n       description: 'File integrity: Sudoers file (/etc/sudoers) modified'")
            continue

        # Sudoers drop-in directory modified rule 100022
        if "ossec: agentless: /etc/sudoers.d/" in line:
            output.append("** Phase 3: Completed filtering (rules).\n       id: '100022'\n       level: '12'\n       description: 'File integrity: Sudoers drop-in directory (/etc/sudoers.d/) modified'")
            continue

        # SSH failed password extraction
        m_fail = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
        if m_fail:
            user, ip = m_fail.group(1), m_fail.group(2)
            failed_sshd_events.append({"user": user, "ip": ip, "raw": line})
            continue

        # SSH accepted login extraction
        m_acc = re.search(r"Accepted \S+ for (\S+) from (\S+)", line)
        if m_acc:
            user, ip = m_acc.group(1), m_acc.group(2)
            accepted_sshd_events.append({"user": user, "ip": ip, "raw": line})
            continue

    # Evaluate correlation / frequency rules across the feed
    # Rule 100040: Critical login after burst brute-force (same IP)
    if accepted_sshd_events and len(failed_sshd_events) >= 8:
        for acc in accepted_sshd_events:
            matching_fails = [f for f in failed_sshd_events if f["ip"] == acc["ip"]]
            if len(matching_fails) >= 8:
                output.append("** Phase 3: Completed filtering (rules).\n       id: '100040'\n       level: '14'\n       description: 'sshd: CRITICAL - Successful login following burst brute-force attack from same IP'")

    # Rule 100041: Critical login after persistent low-and-slow brute-force (same IP)
    if accepted_sshd_events and len(failed_sshd_events) >= 5:
        for acc in accepted_sshd_events:
            matching_fails = [f for f in failed_sshd_events if f["ip"] == acc["ip"]]
            if 5 <= len(matching_fails) < 8:
                output.append("** Phase 3: Completed filtering (rules).\n       id: '100041'\n       level: '14'\n       description: 'sshd: CRITICAL - Successful login following low-and-slow brute-force attack from same IP'")

    # Rule 100010: Burst brute force (>= 8 failures from same IP)
    if len(failed_sshd_events) >= 8:
        # Check if same IP
        ips = [f["ip"] for f in failed_sshd_events]
        for ip in set(ips):
            if ips.count(ip) >= 8:
                output.append("** Phase 3: Completed filtering (rules).\n       id: '100010'\n       level: '10'\n       description: 'sshd: High-frequency burst brute-force attack detected'")

    # Rule 100014: Single account targeting (>= 8 failures on same user across distinct IPs)
    if len(failed_sshd_events) >= 8:
        users = [f["user"] for f in failed_sshd_events]
        for u in set(users):
            if users.count(u) >= 8:
                output.append("** Phase 3: Completed filtering (rules).\n       id: '100014'\n       level: '11'\n       description: 'sshd: High-frequency authentication failures targeting a single username'")

    # Rule 100012: Low-and-slow brute force (>= 5 failures from same IP)
    if 5 <= len(failed_sshd_events) < 8:
        ips = [f["ip"] for f in failed_sshd_events]
        for ip in set(ips):
            if ips.count(ip) >= 5:
                output.append("** Phase 3: Completed filtering (rules).\n       id: '100012'\n       level: '10'\n       description: 'sshd: Low-and-slow persistent brute-force attack detected'")

    # If nothing triggered above, return default base rule
    if not output:
        output.append("** Phase 3: Completed filtering (rules).\n       id: '5760'\n       level: '5'\n       description: 'sshd: Attempt to login using a non-existent user'")

    return "\n\n".join(output)

if __name__ == "__main__":
    content = sys.stdin.read()
    print(evaluate(content))
