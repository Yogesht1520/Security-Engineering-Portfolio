# SOC Incident Investigation Case Report

**Case ID:** INC-2026-0814  
**Date of Incident:** 2026-08-14  
**Lead Analyst:** SOC / Detection Engineering  
**Subject:** High-Volume Automated SSH Brute Force Campaign against Public Honeypot  
**Primary Indicator:** Source IP `34.106.64.73`  
**Classification:** Credential Access (MITRE ATT&CK [T1110.001](https://attack.mitre.org/techniques/T1110/001/))  
**Final Disposition:** **P3 — Opportunistic Scanner Activity (No Compromise / Baseline Preserved)**

---

## 1. Initial Alert & Trigger

At **08:14:22 UTC**, the Wazuh SIEM fired recurring alerts matching:
- **Rule ID `5716`:** *sshd: authentication failed* (Frequency spike)
- **Rule ID `5710`:** *sshd: Attempt to login using a non-existent user*
- **Aggregate Volume:** 256 failed authentication attempts logged within 93 minutes.

Target Host: `siem-lab-honeypot` (`10.0.1.10`)  
Attacking Source: `34.106.64.73:48922` (Origin: United States / Cloud Provider)

---

## 2. Chronological Timeline of Events

| Timestamp (UTC) | Event Source | Event Description | Raw Telemetry / Rule ID |
|:---|:---|:---|:---|
| **08:14:22** | `sshd` | Initial connection established; failed password for user `root` | Rule `5716` |
| **08:16:05** | `sshd` | High-frequency password attempts for `root` (4 attempts) | Rule `5716` |
| **08:29:40** | `sshd` | Shift in targeted accounts to cloud defaults: `ubuntu`, `admin` | Rule `5710` |
| **08:44:11** | `sshd` | Service account probe: `wazuh-dashboard`, `postgres` | Rule `5710` |
| **09:12:35** | `sshd` | Paced password guesses (1 attempt every 90 seconds) | Rule `5716` (Evading 120s burst rule) |
| **09:47:19** | `sshd` | Final connection dropped; scanning ceased | Connection closed by remote host |
| **09:50:00** | Analyst Triage | Incident opened, scoping initiated across SIEM cluster | Triage Playbook PB-SOC-001 |

---

## 3. Threat Actor Infrastructure & Target Analysis

### A. Source Infrastructure Intelligence
- **Source IP:** `34.106.64.73`
- **Reverse DNS:** `73.64.106.34.bc.googleusercontent.com`
- **ASN:** AS15169 (Google LLC)
- **Threat Reputation (AbuseIPDB):** Confidence of Abuse 100%; reported >1,400 times for automated SSH credential brute forcing across global honeypots.
- **SSH Client Banner:** `SSH-2.0-libssh_0.9.5` (Standard programmatic credential stuffing library).

### B. Targeted Usernames & Attack Vector
Of the 256 attempts:
- `root`: 150 attempts (58.6%) — attempting standard dictionary passwords (`123456`, `password`, `toor`, `admin123`)
- `ubuntu`: 25 attempts (9.8%) — attempting cloud-init default credentials
- `wazuh-dashboard`: 10 attempts (3.9%) — probing for default application service users
- Unassigned / service names: 71 attempts (27.7%)

---

## 4. Correlated Forensic Analysis & Scoping

To verify whether any attempts succeeded or if lateral expansion occurred, three forensic queries were executed across the SIEM dataset:

### Query 1: Authentication Success Verification
```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "rule.id": "5715" } },
        { "match": { "data.srcip": "34.106.64.73" } }
      ]
    }
  }
}
```
**Result:** **0 hits.** No successful logins occurred from `34.106.64.73`.

### Query 2: Correlation Rule 100040 (Login After Brute Force)
**Result:** **0 hits.** The alert did not fire for this attacker IP. (The only firing of `100040` during the 24h period was during controlled synthetic validation).

### Query 3: Process Execution Telemetry on Honeypot (`auditd`)
Inspected `/var/log/audit/audit.log` between 08:14 and 10:00 UTC:
- **Result:** No unexpected child processes, reverse shells, `wget`, or file modifications occurred during this timeframe.

---

## 5. Working Hypotheses & Evidence Evaluation

| Hypothesis | Supporting Evidence | Contradicting Evidence | Conclusion |
|:---|:---|:---|:---|
| **H1: Targeted Intrusion Campaign** | Probed for specific installed service user (`wazuh-dashboard`). | Connection banner is automated `libssh`; passwords tested are standard dictionary lists; scanning ceased abruptly. | **Rejected** |
| **H2: Opportunistic Automated Botnet / Cloud Scanner** | Consistent pacing; high abuse reputation across community; targeting standard Unix accounts (`root`, `ubuntu`). | None. | **Supported** |

---

## 6. Incident Disposition & Action Plan

### Final Disposition: **P3 — Opportunistic Scanner Activity (Contained / Closed)**
No breach occurred. Password authentication was disabled by design on the honeypot, ensuring credential guessing attempts had a 0% mathematical probability of success.

### Remediation & Engineering Enhancements Taken:
1. **Network Shunning:** Added `34.106.64.73` to the host iptables drop table via Wazuh Active Response.
2. **Detection Rule Tuning:** Observed that the botnet throttled attempts to 1–3 every 90 seconds, evading the original Rule `100010` threshold (8 in 120s). Developed and deployed **Rule `100012`** (5 in 1 hour) to catch low-and-slow persistent scanners.
3. **Abuse Reporting:** Submitted threat telemetry and log samples to the hosting provider abuse contact.
