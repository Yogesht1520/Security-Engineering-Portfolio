# SIEM Lab Detection Rules & Engineering Architecture

This document details the custom detection rules deployed in the SIEM lab, mapping them to the MITRE ATT&CK framework and explaining the engineering decisions behind their thresholds and correlations.

---

## 1. Multi-Tiered SSH Detection Architecture

Real-world honeypot observations revealed that automated scanners and botnets deliberately pace their authentication attempts (1–3 attempts every few minutes) to bypass traditional high-frequency burst detection rules. In response, the detection architecture was upgraded to a multi-tiered defense:

| Detection Tier | Rule ID | Target Adversary Behavior | Timeframe & Threshold | False Positive Strategy |
|:---|:---:|:---|:---|:---|
| **Burst Brute Force** | `100010` | High-volume botnets / crude automated tools attempting rapid credential stuffing | 8+ failures in 120s from same IP | Exclude known management IPs |
| **Low & Slow Brute Force** | `100012` | Throttled botnets pacing attempts to evade short-window thresholds | 5+ failures in 3600s (1h) from same IP | Correlate with GeoIP / reputation |
| **Distributed Password Spray** | `100014` | Botnets using multiple egress nodes targeting a single high-value account | 8+ failures in 300s across IPs for same user | Filter common service accounts |
| **Benign Admin Baseline** | `100015` | Expected administrative access from internal management networks | Level 3 baseline logging | Whitelist VPC management CIDR |
| **Attack Progression Correlation**| `100040` / `100041` | Authentication success following either burst or slow brute-force attack | Immediate correlation on same source IP | Analyze key vs password auth |

---

## 2. MITRE ATT&CK Coverage Matrix

| Rule ID | Detection Name | ATT&CK Technique | Severity | Status |
|:-------:|----------------|:-----------------|:--------:|:------:|
| `100010` | SSH Burst Brute Force | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) (Password Guessing) | Level 10 | ✅ Deployed |
| `100012` | SSH Low & Slow Brute Force | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) (Password Guessing) | Level 10 | ✅ Deployed |
| `100014` | Distributed SSH Password Spray | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Password Spraying) | Level 11 | ✅ Deployed |
| `100015` | Benign Admin SSH Access | N/A (Baseline Telemetry) | Level 3 | ✅ Deployed |
| `100020` | New User Created | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) (Create Account: Local Account) | Level 8 | ✅ Deployed |
| `100021` | Sudoers Modified | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) (Sudo and Sudo Caching) | Level 12 | ✅ Deployed |
| `100030` | Suspicious Command Exec | [T1059](https://attack.mitre.org/techniques/T1059/) (Command and Scripting Interpreter) | Level 12 | ✅ Deployed |
| `100040` | Success After Burst Brute Force | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) & [T1078](https://attack.mitre.org/techniques/T1078/) | Level 14 | ✅ Deployed |
| `100041` | Success After Slow Brute Force | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) & [T1078](https://attack.mitre.org/techniques/T1078/) | Level 14 | ✅ Deployed |

---

## 3. Detailed Rule Specifications

### Rule 100010: SSH Burst Brute Force Aggregation
- **Log Source:** `/var/log/auth.log` (sshd)
- **Logic:** Matches base rule `5716` (sshd authentication failed) aggregated by `same_source_ip` (frequency: 8, timeframe: 120s).
- **Triage Action:** Check whether source IP is internal or external. Query IP reputation (AbuseIPDB, VirusTotal).

### Rule 100012: SSH Low-and-Slow Persistent Brute Force
- **Log Source:** `/var/log/auth.log` (sshd)
- **Logic:** Matches base rule `5716` aggregated by `same_source_ip` (frequency: 5, timeframe: 3600s).
- **Triage Action:** Designed specifically to close the gap where botnets pace attempts to evade short-window thresholds.

### Rule 100014: Distributed Password Spray
- **Log Source:** `/var/log/auth.log` (sshd)
- **Logic:** Matches base rule `5716` aggregated by `same_user` across diverse source IPs (frequency: 8, timeframe: 300s).
- **Triage Action:** Identify if a targeted user account is receiving credential attempts from coordinated botnets or residential proxy networks.

### Rule 100020: New User Created
- **Log Source:** `auditd`
- **Logic:** Triggers on `auditd` syscall events matching `/usr/sbin/useradd` execution.
- **Triage Action:** Verify against change management tickets or administrative maintenance windows.

### Rule 100021: Sudoers Configuration Modified
- **Log Source:** Wazuh FIM (Syscheck)
- **Logic:** Triggers on File Integrity Monitoring alerts for modifications to `/etc/sudoers` or drop-in files in `/etc/sudoers.d/`.
- **Triage Action:** Inspect file diff to verify added permissions (e.g. `NOPASSWD: ALL` indicates privilege escalation persistence).

### Rule 100030: Suspicious Living-Off-The-Land Command
- **Log Source:** `auditd`
- **Logic:** Triggers on execution of living-off-the-land utilities (`wget`, `curl`, `nc`, `ncat`) typically used for payload retrieval or reverse shells.
- **Triage Action:** Inspect process execution arguments and parent process tree.

### Rule 100040 & 100041: Login After Brute Force
- **Log Source:** Correlated `sshd` auth logs
- **Logic:** Triggers when rule `5715` (authentication success) occurs from a source IP that previously triggered rule `100010` (burst) or `100012` (slow brute force).
- **Triage Action:** High priority investigation. Correlate whether login was password-based or key-based, and verify source IP authenticity. See [SOC Playbook](playbooks/SSH_BRUTE_FORCE.md).
