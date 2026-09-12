# 24-Hour Honeypot Observation Report

> **Goal:** Document real-world attack patterns collected by the honeypot over a 24-hour period. This proves analytical ability for a SOC / Blue Team role. Do not fabricate numbers—only report what your lab actually observed.

## 1. Executive Summary
From the deployment of the lab environment, the internet-facing honeypot was exposed to gather background threat intelligence for approximately 24 hours. The environment collected over 590 events, dominated by automated SSH brute-forcing attempts from various global botnets. The primary objective was to observe automated scanning behavior and validate the custom SIEM detection rules against real-world traffic.

## 2. Authentication Attack Analytics
*Use the Wazuh Dashboard to extract these metrics:*

- **Total Events/Alerts:** ~632
- **SSH Authentication Failures (Brute Force):** 315
- **Successful Logins:** 13 (Authorized lab administration)
- **Peak Attack Period:** 08:00 – 10:00 UTC (Massive spike in brute-force scanning)
- **Top Aggressor IP:** `34.106.64.73` (Accounted for 256 attempts)

## 3. Top Attacker Demographics
*(Check Wazuh -> Modules -> Security Events -> Dashboard for GeoIP data)*

**Top 5 Attacking Countries (by volume):**
1. United States
2. United Kingdom
3. Russia
4. Iran
5. India

*(Note: Country origin is derived from GeoIP lookups on source IP addresses. It does not definitively indicate the nationality of the attacker, as botnets utilize compromised infrastructure globally).*

## 4. SSH Brute-Force Tactics
*(Filter alerts by Rule 100010 or 5716)*

**Top 5 Usernames Targeted:**
*(Attackers rely heavily on default credentials and standard Linux service accounts)*
1. `root` (~150 attempts)
2. `ubuntu` (~25 attempts)
3. `wazuh-dashboard` (~10 attempts)
4. `by` (~3 attempts)
5. `testattacker` (1 attempt)

## 5. Detection Performance
*(Document how your custom rules performed)*

| Rule ID | Detection Name | Trigger Count | False Positives |
|---------|----------------|---------------|-----------------|
| `100010` | SSH Brute Force Aggregation | 1 (Synthetic Test) | 0 |
| `100020` | New User Created | 1 (Synthetic Test) | 0 |
| `100021` | Sudoers Modified | 1 (Synthetic Test) | 0 |
| `100030` | Suspicious Command | 1 (Synthetic Test) | 0 |
| `100040` | Login After Brute Force | 1 (Synthetic Test) | 0 |

*Note: While real SSH auth failures triggered stock rules (e.g., Rule 5760, 5710), the custom Rule `100010` only triggered during synthetic testing. This highlights that real-world automated scanners often pace their attacks (e.g., 2-3 attempts per IP) to evade aggressive thresholds (8 attempts in 120s).*

## 6. MITRE ATT&CK Mapping
*(Check Wazuh -> Modules -> MITRE ATT&CK)*

**Techniques Observed:**
- **[T1110.001](https://attack.mitre.org/techniques/T1110/001/) (Password Guessing):** Triggered ~280 times by automated botnets attempting to guess SSH credentials.
- **[T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts):** Triggered 13 times (Lab administration).
- **[T1531](https://attack.mitre.org/techniques/T1531/) (Account Access Removal):** Triggered during synthetic testing.

## 7. Conclusion & Remediation
*Internet-facing SSH services receive near-instantaneous automated scanning and authentication attempts upon deployment. The volume of attacks highlights the necessity of hardening internet-facing services.*

**Recommended Remediation for Production Environments:**
1. Disable SSH password authentication entirely; mandate key-based auth.
2. Implement restrictive network firewalls (e.g., GCP VPC Firewall) to only allow SSH from known administrative IPs or a corporate VPN.
3. Deploy an intrusion prevention system like Fail2Ban or CrowdSec to automatically drop connections from aggressive IPs.
4. Move SSH from the default port 22 to a non-standard port to avoid untargeted background scanning noise.
