# Enterprise SIEM & Threat Detection Engineering Lab

[![CI - Terraform](https://github.com/Yogesht1520/Security-Engineering-Portfolio/actions/workflows/validate-terraform.yml/badge.svg)](.github/workflows/validate-terraform.yml)
[![CI - ShellCheck](https://github.com/Yogesht1520/Security-Engineering-Portfolio/actions/workflows/validate-shell.yml/badge.svg)](.github/workflows/validate-shell.yml)
[![CI - Wazuh Rules](https://github.com/Yogesht1520/Security-Engineering-Portfolio/actions/workflows/validate-wazuh-rules.yml/badge.svg)](.github/workflows/validate-wazuh-rules.yml)
[![CI - Security Gate](https://github.com/Yogesht1520/Security-Engineering-Portfolio/actions/workflows/security.yml/badge.svg)](.github/workflows/security.yml)

An enterprise-grade, end-to-end Security Operations Center (SOC) and Detection Engineering laboratory deployed in Google Cloud Platform (GCP). The lab exposes an intentionally instrumented Linux honeypot to capture live internet attack campaigns, processes raw kernel audit and authentication telemetry through a unified Wazuh SIEM stack, and correlates multi-stage intrusions using custom MITRE ATT&CK-mapped detection rules, automated response runbooks, and interactive operational dashboards.

---

## 1. System Architecture

```mermaid
flowchart TD
    subgraph Internet["Public Internet"]
        ATK1["Attacker: 209.99.190.186 (Switzerland)"]
        ATK2["Scanner: 80.94.92.234 (Automated Probes)"]
    end

    subgraph GCP["Google Cloud Platform — VPC Subnet (10.0.1.0/24)"]
        subgraph DMZ["Exposed DMZ Perimeter"]
            Honeypot["Honeypot VM (10.0.1.3 / 34.121.64.158)\n• SSH Ingress: 0.0.0.0/0\n• auditd, auth.log, syslog\n• Wazuh Agent 4.9.2-1 (Pinned)"]
        end

        subgraph HardenedCore["Protected Management & SIEM Core"]
            SIEM["Wazuh Manager (10.0.1.2 / 34.71.182.95)\n• OpenSearch Indexer (Internal)\n• Wazuh Analysis Engine (Ruleset 100010–100041)\n• OpenSearch Dashboards (HTTPS)"]
        end

        subgraph EgressPolicy["Strict Egress Boundary Firewall"]
            EgressDeny["Priority 65534: DENY All Outbound (0.0.0.0/0)"]
            EgressPkg["Priority 1100: ALLOW Apt Updates (TCP 80/443, UDP 53)"]
            EgressSIEM["Priority 1000: ALLOW Internal Telemetry (TCP 1514/1515)"]
            IndexDeny["Priority 800: DENY Public OpenSearch (TCP 9200/9300)"]
        end
    end

    subgraph SOC["SOC Management Plane"]
        Analyst["SOC Analyst / Detection Engineer\n(Restricted Management IP)"]
        Portal["Interactive SOC Analytics Portal\n(dashboards/index.html)"]
        CaseMgmt["Incident Case Manager\n(incident_management/case_manager.py)"]
    end

    ATK1 -->|T1110 Paced Dictionary Attack| Honeypot
    ATK2 -->|T1110 Automated Banner Scanning| Honeypot
    Honeypot -->|Encrypted Agent Logs (TCP 1514)| SIEM
    SIEM -->|Alert Correlation & Telemetry| Analyst
    Analyst --> Portal
    Analyst --> CaseMgmt
```

---

## 2. Evidence & Verification Matrix

Every detection capability and incident response workflow in this lab is backed by verified machine-readable test artifacts, cryptographic manifests, and real-world attack telemetry:

| Artifact Type | File / Location | Description & Integrity |
| :--- | :--- | :--- |
| **Forensic Evidence Bundle** | [`evidence/20261026_194434/`](evidence/20261026_194434/) | Real captured logs: `honeypot_audit.log` (6.5MB), `honeypot_auth.log` (49KB), `wazuh_alerts.json` (1.16MB), and `honeypot_system_state.txt`. |
| **Cryptographic Manifest** | [`evidence/.../SHA256SUMS.txt`](evidence/20261026_194434/SHA256SUMS.txt) | SHA-256 hashes verifying forensic chain of custody for all preserved artifacts. |
| **Active Incident Case** | [`incident_management/cases/CASE-2026-001.json`](incident_management/cases/CASE-2026-001.json) | High-severity case opened and contained against live attacker `209.99.190.186` (Zurich, Switzerland). |
| **Unit Test Suite Results** | [`tests/results/unit_test_20261026_191220.json`](tests/results/unit_test_20261026_191220.json) | Automated execution of 6 detection unit tests against `wazuh-logtest` (**6/6 Passed**). |
| **Static Rule Audit** | `python tests/validate_rules.py` | Validates XML syntax, duplicate rule IDs, and ID range enforcement (**10/10 Passed**). |
| **Security Leak Gate** | `python tests/security_scan.py` | Scans git index for leaked secrets, API keys, `.tfstate`, and `.tfvars` (**Zero Leaks**). |

---

## 3. Detection Catalog & MITRE ATT&CK Mapping

Custom detection rules deployed in `/var/ossec/etc/rules/` are documented in the [Detection Catalog](detections/catalog/):

| Rule ID | Detection Name | Level | MITRE Tactic | Technique ID | Catalog Specification |
| :---: | :--- | :---: | :--- | :---: | :--- |
| **100010** | Burst SSH Brute Force (8+ in 120s) | 10 | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | [`DET-SSH-001`](detections/catalog/authentication/DET-SSH-001_burst-brute-force.md) |
| **100012** | Low-and-Slow Persistent Brute Force | 10 | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | [`DET-SSH-002`](detections/catalog/authentication/DET-SSH-002_low-and-slow.md) |
| **100014** | Targeted Account Failure Concentration | 11 | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | [`DET-SSH-003`](detections/catalog/authentication/DET-SSH-003_repeated-failures-same-user.md) |
| **100015** | Benign Management Authentication | 3 | Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Whitelist rule for SIEM host IP |
| **100020** | Local User Account Creation | 8 | Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | [`DET-PRIV-001`](detections/catalog/privilege_escalation/DET-PRIV-001_user-creation.md) |
| **100021** | Sudoers Configuration Modification | 12 | Privilege Escalation | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | [`DET-PRIV-002`](detections/catalog/privilege_escalation/DET-PRIV-002_sudoers-modification.md) |
| **100022** | Sudoers Drop-in Directory Change | 12 | Privilege Escalation | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | [`DET-PRIV-002`](detections/catalog/privilege_escalation/DET-PRIV-002_sudoers-modification.md) |
| **100030** | Suspicious Command Execution | 12 | Execution | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | [`DET-EXEC-001`](detections/catalog/execution/DET-EXEC-001_suspicious-commands.md) |
| **100040** | CRITICAL: Success After Burst Attack | 14 | Credential Access / Lateral | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/) | [`DET-SSH-004`](detections/catalog/authentication/DET-SSH-004_success-after-attack.md) |
| **100041** | CRITICAL: Success After Slow Attack | 14 | Credential Access / Lateral | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/) | [`DET-SSH-004`](detections/catalog/authentication/DET-SSH-004_success-after-attack.md) |

---

## 4. Visualizations & Operational Dashboards

The lab features dual operational visualization interfaces:

### 4.1 Standalone Interactive SOC Analytics Portal
Located at [`dashboards/index.html`](dashboards/index.html), this client-side portal runs locally in any web browser without needing cloud infrastructure.
- **Glassmorphism Theme:** Dark obsidian layout with cyan and purple neon metrics.
- **Interactive Visualizations:**
  - *Attack Volume Timeline:* Hourly progression of security events.
  - *MITRE ATT&CK Matrix Doughnut:* Distribution across Credential Access, Lateral Movement, and Privilege Escalation.
  - *Targeted Usernames Bar Chart:* Probed accounts (`root`, `ubuntu`, `sysadmin`, `var`, `vor`, `www`).
  - *Threat Intelligence Table:* Live ASN and GeoIP summaries for active scanners (`209.99.190.186`).
- **Telemetry Explorer:** Real-time search query box, severity filter chips (`All`, `Critical`, `High`, `Medium`, `Low`), raw JSON payload drawer, and incident case modal.

### 4.2 Production OpenSearch Dashboards
Pre-configured `.ndjson` dashboard definitions exported for Wazuh / OpenSearch Dashboards:
- [`wazuh/dashboards/soc_threat_overview.ndjson`](wazuh/dashboards/soc_threat_overview.ndjson): Executive SOC overview.
- [`wazuh/dashboards/ssh_bruteforce_deepdive.ndjson`](wazuh/dashboards/ssh_bruteforce_deepdive.ndjson): Credential access analytics.
- Automated import script:
  ```bash
  bash wazuh/dashboards/import_dashboards.sh <SIEM_PUBLIC_IP> <WAZUH_PASSWORD>
  ```

![Live OpenSearch SOC Threat Overview Dashboard](screenshots/live_soc_threat_overview.png)

---

## 5. Incident Management & Response Tooling

The [`incident_management/`](incident_management/) subsystem provides structured tools for triaging and containing security events:

```text
incident_management/
├── case_schema.json          # Formal JSON Schema specification for incident cases
├── case_manager.py           # CLI tool for creating, viewing, and resolving cases
├── cases/
│   └── CASE-2026-001.json    # Real contained incident case
├── enrichment/
│   ├── geoip.py              # Geolocation & ASN resolver
│   └── reputation.py         # AbuseIPDB reputation API client
├── reports/
│   └── incident_report_template.md  # Standardized NIST SP 800-61 Rev. 2 post-mortem template
└── response/
    ├── preserve_evidence.sh  # Automated forensic snapshot runbook
    ├── isolate_honeypot.sh   # Emergency host & GCP firewall quarantine tool
    └── rebuild_honeypot.sh   # Evidence-preserving instance rebuild tool
```

### CLI Incident Workflow Example:
```bash
# 1. List active incident cases
python incident_management/case_manager.py --list

# 2. View specific case details and timeline
python incident_management/case_manager.py --view CASE-2026-001

# 3. Apply emergency honeypot network isolation
bash incident_management/response/isolate_honeypot.sh --all

# 4. Safely rebuild honeypot after preserving evidence
bash incident_management/response/rebuild_honeypot.sh
```

---

## 6. CI/CD Pipeline & Automated Quality Gates

All infrastructure code, scripts, and detection rules are validated via GitHub Actions with pinned action SHAs:

1. [**Validate Terraform**](.github/workflows/validate-terraform.yml): Runs `terraform fmt -check`, `terraform init -backend=false`, and `terraform validate`.
2. [**Validate Shell Scripts**](.github/workflows/validate-shell.yml): Executes `shellcheck --severity=warning` across all shell scripts.
3. [**Validate Wazuh Rules**](.github/workflows/validate-wazuh-rules.yml): Executes `tests/validate_rules.py` for XML syntax and duplicate ID prevention.
4. [**Security Gate**](.github/workflows/security.yml): Executes `tests/security_scan.py` to prevent accidental credential or `.tfstate` leaks.

---

## 7. Lifecycle Operations & Teardown

For full step-by-step instructions on provisioning, bootstrapping software, running tests, and safely destroying the lab, refer to:
- [**SIEM Lab Safe Restart Guide**](docs/RESTART_GUIDE.md)
- [**Honeypot Isolation & Safety Guide**](docs/HONEYPOT_ISOLATION_AND_SAFETY.md)
- [**Lab Access Details Template**](docs/LAB_ACCESS_DETAILS.md.example)

> [!CAUTION]
> **Mandatory Rule:** Always run `bash incident_management/response/preserve_evidence.sh` before running `terraform destroy` to ensure no forensic attack evidence is lost upon teardown.
