# SIEM Lab Detection Rules

This document details the custom detection rules deployed in the SIEM lab, mapping them to the MITRE ATT&CK framework and providing operational context for analysts.

## MITRE ATT&CK Coverage Matrix

| Rule ID | Detection Name | ATT&CK Technique | Status |
|---------|----------------|------------------|--------|
| `100010` | SSH Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force) | ✅ Deployed |
| `100020` | New User Created | [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) | ✅ Deployed |
| `100021` | Sudoers Modified | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) (Sudo and Sudo Caching) | ✅ Deployed |
| `100030` | Suspicious Command | [T1059](https://attack.mitre.org/techniques/T1059/) (Command and Scripting Interpreter) | ✅ Deployed |
| `100040` | Login After Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) & [T1078](https://attack.mitre.org/techniques/T1078/) | ✅ Deployed |

---

## Detailed Rule Documentation

### Rule 100010: SSH Brute Force (Example of Full Documentation)

| Field | Value |
|-------|-------|
| **Rule ID** | `100010` |
| **Detection Name** | SSH Brute Force Aggregation |
| **Severity** | High (Level 10) |
| **MITRE ATT&CK** | T1110 - Brute Force |
| **Log Source** | `/var/log/auth.log` (via syslog/sshd) |
| **Detection Logic** | Time-based aggregation of `sshd` authentication failures. |
| **Trigger Condition** | 8+ authentication failures from the same source IP within a 120-second window. |
| **Expected False Positives** | Legitimate administrator repeatedly mistyping a password or using a misconfigured automation script. |
| **Example Event** | `sshd: High-frequency brute-force attack detected from 192.168.1.55.` |
| **Investigation Steps** | 1. Identify source IP.<br>2. Check usernames targeted (are they valid system accounts?).<br>3. Look for a subsequent successful login (Rule `100040`).<br>4. Review commands executed if login was successful. |
| **Response Recommendation** | Block source IP via firewall or fail2ban. Investigate if targeted accounts were compromised. |

---

### Concise Rule References

#### Rule 100020: New User Created
- **Severity:** Medium (Level 8)
- **MITRE:** T1078
- **Logic:** Triggers on `auditd` events where `/usr/sbin/useradd` is executed.
- **Investigation:** Verify if the user creation was part of a scheduled maintenance window or requested by an authorized administrator.

#### Rule 100021: Sudoers Modified
- **Severity:** High (Level 12)
- **MITRE:** T1548.003
- **Logic:** Triggers on File Integrity Monitoring (FIM) alerts for changes to `/etc/sudoers` or files in `/etc/sudoers.d/`.
- **Investigation:** Check who modified the file and what permissions were added. An attacker may be creating a backdoor for future privilege escalation.

#### Rule 100030: Suspicious Command Execution
- **Severity:** High (Level 12)
- **MITRE:** T1059
- **Logic:** Triggers on `auditd` events for execution of living-off-the-land tools like `wget`, `curl`, `nc`, or `ncat`.
- **Investigation:** Review the command line arguments to see what was downloaded or if a reverse shell was initiated. Correlate with recent logins.

#### Rule 100040: Login After Brute Force
- **Severity:** Critical (Level 14)
- **MITRE:** T1110 & T1078
- **Logic:** Correlates a successful SSH login (Rule `5715`) immediately following a brute-force alert (Rule `100010`) from the same IP.
- **Investigation:** **CRITICAL INCIDENT.** Immediate containment required. Assume the host is compromised. Isolate the machine, identify the compromised account, and begin incident response procedures.
