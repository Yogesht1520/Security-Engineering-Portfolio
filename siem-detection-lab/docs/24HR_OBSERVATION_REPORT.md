# 24-Hour Honeypot Observation Report

**Environment:** Internet-Facing GCP Honeypot (Ubuntu 22.04 LTS)  
**SIEM Platform:** Wazuh Stack (Manager, Indexer, Dashboard v4.7+)  
**Monitoring Window:** 24 Hours Continuous Collection  
**Report Type:** Threat Intelligence & Detection Efficacy Analysis  

---

## 1. Executive Summary

Over a 24-hour observation window, the internet-facing honeypot was exposed to the public internet with port 22 (SSH) open to capture live adversary behavior. The SIEM ingested **590 raw authentication log events**, resulting in **632 normalized security alerts** (including rule aggregations and correlation alerts). 

Traffic was dominated by automated botnet scanning and dictionary password guessing. The primary objective was twofold:
1. Observe opportunistic adversary scanning patterns in the wild.
2. Benchmark custom Wazuh detection rules against real-world attack pacing versus synthetic attack simulations.

---

## 2. Authentication Attack Analytics

- **Total Normalized Alerts:** 632
- **Raw SSH Authentication Failures:** 315
- **Authorized Administrative Sessions:** 13 (Conducted from dedicated analyst management IP)
- **Peak Attack Activity:** 08:00 – 10:00 UTC (Mass automated credential stuffing campaign)
- **Top Aggressor IP:** `34.106.64.73` (Accounted for 256 failed attempts; 81.2% of total brute-force volume)

---

## 3. Threat Demographics & GeoIP Distribution

GeoIP enrichment via Wazuh's MaxMind integration revealed traffic originating across multiple distinct geographies. 

| Rank | Country of Origin | Share of Traffic | Primary Behavior Observed |
|------|-------------------|------------------|---------------------------|
| 1 | United States | ~48% | Automated cloud-hosted scanner nodes (`34.106.64.73`) |
| 2 | United Kingdom | ~22% | Multi-IP credential stuffing |
| 3 | Russia | ~14% | Low-and-slow root dictionary sweeps |
| 4 | Iran | ~9% | Service account probes |
| 5 | India | ~7% | Distributed single-attempt credential checks |

> **Analyst Note:** GeoIP localization reflects the egress IP of the scanning infrastructure (often compromised cloud VMs, residential proxies, or open relays) rather than the physical location of the threat actor.

---

## 4. Adversary Tactics & Targeted Accounts

Adversary tooling targeted predictable default accounts, administrative users, and installed service accounts.

| Targeted Account | Attempt Count | Target Classification | Analyst Assessment |
|------------------|---------------|-----------------------|---------------------|
| `root` | ~150 | Default Superuser | Primary dictionary attack target; high risk if passwords permitted |
| `ubuntu` | ~25 | Default Cloud OS User | Targeted GCP/AWS default username assumption |
| `wazuh-dashboard`| ~10 | Service Account | Probing for default credentials of the SIEM UI service |
| `by` | ~3 | Typo / Short Account | Residual dictionary payload artifact |
| `testattacker` | 1 | Controlled Account | Verification probe during lab validation |

---

## 5. Detection Rule Performance & Gap Analysis

Rather than assuming zero false positives based on a single synthetic test, the table below delineates synthetic validation results, real-world match counts, and operational tuning notes.

| Rule ID | Detection Name | MITRE Technique | Synthetic Validation | Real-World Matches | False Positive Assessment & Tuning Notes |
|:-------:|----------------|:---------------:|:--------------------:|:------------------:|-------------------------------------------|
| `100010` | SSH Brute Force Aggregation | [T1110](https://attack.mitre.org/techniques/T1110/) | ✅ Passed (1 alert) | 0 alerts | **Detection Gap Identified:** Real scanners throttled connection rates (1–3 attempts every few minutes) to stay below the 8-attempts-in-120s threshold. *Tuning action: deploy low-and-slow correlation rule.* |
| `100020` | New User Created | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | ✅ Passed (1 alert) | 0 alerts | 0 observed in production. Fired cleanly on auditd `useradd` execution during test. |
| `100021` | Sudoers File Modified | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | ✅ Passed (1 alert) | 0 alerts | 0 observed. FIM detected drop-in modification without false alerts during routine system maintenance. |
| `100030` | Suspicious Command Exec | [T1059](https://attack.mitre.org/techniques/T1059/) | ✅ Passed (1 alert) | 0 alerts | 0 observed. In production, requires whitelist tuning for legitimate package manager download operations. |
| `100040` | Login After Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) & [T1078](https://attack.mitre.org/techniques/T1078/) | ✅ Passed (1 alert) | 0 alerts | 0 observed from attacker IPs. Successfully baseline-tested: 13 authorized administrator sessions did not trigger false alarms due to IP matching. |

### Engineering Insight: The Threshold Evasion Gap
While Wazuh built-in rules (Rule 5716: *SSHD authentication failed*, Rule 5710: *SSHD host brute force*) triggered on raw volume, custom rule `100010` (8 attempts / 120s) demonstrated that **adversaries actively circumvent aggressive short-window thresholds**. 

This operational finding informed the creation of a tiered detection strategy:
1. **Burst Brute Force (`100010`):** High frequency (8+ in 2 mins) — catches crude, noisy botnets.
2. **Low-and-Slow Brute Force (`100012`):** Lower frequency over extended window (5+ in 1 hour) — catches evasive botnets.
3. **Distributed Credential Spray (`100014`):** Failures across multiple IPs targeting common users.

---

## 6. MITRE ATT&CK Mapping & Coverage

| Technique ID | Technique Name | Tactic | Observation Source |
|:------------:|----------------|:------:|:------------------:|
| **[T1110.001](https://attack.mitre.org/techniques/T1110/001/)** | Password Guessing | Credential Access | 315 live failed auth attempts from external scanner IPs |
| **[T1078](https://attack.mitre.org/techniques/T1078/)** | Valid Accounts | Initial Access / Defense Evasion | 13 authorized maintenance sessions (audited via public key) |
| **[T1136.001](https://attack.mitre.org/techniques/T1136/001/)** | Create Account: Local Account | Persistence | Controlled synthetic test validation via `useradd` |
| **[T1548.003](https://attack.mitre.org/techniques/T1548/003/)** | Sudo and Sudo Caching | Privilege Escalation | Controlled synthetic FIM test validation |
| **[T1059](https://attack.mitre.org/techniques/T1059/)** | Command & Scripting Interpreter | Execution | Controlled synthetic test validation (`wget`) |

---

## 7. Strategic Recommendations & Production Hardening

1. **Eliminate Password Authentication:** Mandate ED25519 or RSA-4096 SSH key authentication; disable `PasswordAuthentication` in `sshd_config`.
2. **Network Perimeter Ingress Restrictions:** Restrict administrative SSH access to static VPN or bastion jump-hosts via cloud firewall rules.
3. **Automated Host-Level Shunning:** Deploy `fail2ban` or Wazuh Active Response to automatically drop IP traffic at the iptables level after 3 sequential failures.
4. **Port Re-allocation:** Moving SSH to a non-standard port (e.g., TCP 2222) reduces automated, untargeted internet background scanning by >95%.
