# Incident Response Investigation Report

**Document Control**
- **Case Reference ID:** {{CASE_ID}}
- **Classification Level:** TLP:AMBER / Internal Security Only
- **Incident Severity:** {{SEVERITY}} (Critical / High / Medium / Low / Informational)
- **Current Status:** {{STATUS}} (New / Investigating / Contained / Eradicated / Closed)
- **Lead Investigator / Analyst:** {{ANALYST_NAME}}
- **Date / Time Opened:** {{OPENED_AT}}
- **Date / Time Closed:** {{CLOSED_AT}}

---

## 1. Executive Summary

| Attribute | Details |
| :--- | :--- |
| **Primary Incident Category** | {{CATEGORY}} (e.g., Credential Access, Lateral Movement, Execution) |
| **Attacking Entity / Origin** | {{SOURCE_IP}} ({{GEO_LOCATION}} / {{ASN}}) |
| **Target Infrastructure** | {{TARGET_HOST}} ({{TARGET_IP}}) |
| **Business / Operational Impact** | {{IMPACT_LEVEL}} (e.g., Zero disruption; baseline honeypot isolation held) |
| **Data Breach / Compromise** | **No** / Yes |

### High-Level Narrative
Provide a 2-3 paragraph non-technical summary explaining:
1. What occurred (who attempted what and when).
2. How the SIEM / Security Operations team detected the intrusion attempt.
3. What containment or isolation actions were taken, and the final state of the environment.

---

## 2. Threat Vector & Attacker Profiling

### 2.1 Threat Actor Infrastructure
- **Source IP Address:** `{{SOURCE_IP}}`
- **Reverse DNS (PTR):** `{{REVERSE_DNS}}`
- **Geolocation:** `{{CITY}}, {{COUNTRY}}`
- **Autonomous System:** `{{ASN}} ({{ISP}})`
- **AbuseIPDB Reputation:** `{{ABUSEIPDB_SCORE}}%` confidence of abuse ({{TOTAL_REPORTS}} reports)
- **User-Agent / SSH Banner:** `{{CLIENT_BANNER}}`

### 2.2 Attack Methodology & MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name | Observed Indicator / Execution |
| :--- | :--- | :--- | :--- |
| Initial Access | T1190 / T1078 | Exploit Public-Facing App / Valid Accounts | Exploit probes against public SSH / web port |
| Credential Access | T1110.001 | Password Guessing / Brute Force | High-frequency password attempts against wordlists |
| Discovery | T1087.001 | Local Account Discovery | Probing for service accounts (`wazuh-dashboard`, `postgres`, `admin`) |
| Lateral Movement | T1021.004 | SSH / Internal Pivoting | Evaluated: None observed across internal subnet |

---

## 3. Chronological Incident Timeline

All timestamps reported in UTC.

| Timestamp (UTC) | Source / Component | Event Description | Severity / Rule ID |
| :--- | :--- | :--- | :--- |
| `YYYY-MM-DD HH:MM:SS` | Network / SSH | First observed connection from threat IP | Informational |
| `YYYY-MM-DD HH:MM:SS` | Wazuh SIEM | Burst brute force threshold breached | High (Rule 100010) |
| `YYYY-MM-DD HH:MM:SS` | Honeypot OS | Account probing (`root`, `admin`, `service`) | High (Rule 100014) |
| `YYYY-MM-DD HH:MM:SS` | Active Response | Local automated block or operator isolation initiated | Critical / Action |
| `YYYY-MM-DD HH:MM:SS` | SOC Analyst | Case triage initiated and scope validated | Operational |

---

## 4. Telemetry & Evidence Artifacts

### 4.1 Correlated Wazuh Alert Logs
```json
[
  {
    "timestamp": "YYYY-MM-DDTHH:MM:SS.sss+0000",
    "rule": {
      "id": "100010",
      "level": 10,
      "description": "SSH Burst Brute Force Detected (8+ failed attempts in 120s)"
    },
    "agent": { "id": "001", "name": "siem-lab-honeypot" },
    "data": { "srcip": "0.0.0.0" }
  }
]
```

### 4.2 Evidence Preservation & Chain of Custody
- **Evidence Bundle Directory:** `evidence/{{TIMESTAMP}}/`
- **Evidence Manifest (SHA-256):**
```text
<sha256_hash>  honeypot_auth.log
<sha256_hash>  honeypot_audit.log
<sha256_hash>  honeypot_system_state.txt
<sha256_hash>  wazuh_alerts.json
```
- **Preserved By:** `{{PRESERVED_BY}}`
- **Verification Command:** `sha256sum -c SHA256SUMS.txt`

---

## 5. Scoping, Analysis & Hypotheses

### 5.1 Working Hypotheses
| Hypothesis | Supporting Evidence | Refuting Evidence | Disposition |
| :--- | :--- | :--- | :--- |
| **H1: Opportunistic Scanner / Botnet** | Rapid automated pattern, known public abuse reputation | No manual interactive commands | Supported |
| **H2: Targeted Attack against Lab** | Probed specific software accounts | Scanner scanned unrelated targets in same ASN | Refuted |
| **H3: Successful Compromise** | N/A | Zero rule 100040 hits; auth.log confirms 0 successful sessions | Refuted |

---

## 6. Containment, Eradication & Recovery

1. **Containment Measures:**
   - Host-level: IP blocked via iptables / active response.
   - Cloud-level: Honeypot network tag isolation firewall rule validated.
2. **Eradication Measures:**
   - Volatile process check verified no rogue persistent daemons or reverse shells.
   - Host state verified against known clean baseline.
3. **Recovery & Rebuild:**
   - Honeypot reprovisioned or restored cleanly using `incident_management/response/rebuild_honeypot.sh`.

---

## 7. Lessons Learned & Engineering Improvements

- **Detection Rule Improvements:** 
  - (e.g. Added low-and-slow threshold rule to capture evasive scanning below 120s threshold).
- **Hardening Enhancements:**
  - (e.g. Ensure strict egress deny firewall rules remain active to prevent outbound C2 communication).
- **Automation Action Items:**
  - (e.g. Integrate automatic AbuseIPDB reporting into case closure workflow).

---
*Report certified by: SOC Lead / Detection Engineering*  
*Timestamp: {{REPORT_GENERATED_TIMESTAMP}}*
