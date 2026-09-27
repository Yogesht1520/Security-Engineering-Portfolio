# Threat Model & Conditional Access Mapping

## 1. Threat Landscape Overview

In modern enterprise architectures, the network perimeter is fluid. Identity represents the primary security boundary ("Identity is the New Perimeter"). Threat actors actively exploit identity misconfigurations via automated credential stuffing, phishing, session token theft, and legacy protocol exploitation.

This document maps our 5 Conditional Access policies to the **MITRE ATT&CK for Cloud Matrix** and demonstrates the specific attack scenarios mitigated.

---

## 2. MITRE ATT&CK Matrix Mapping

| Threat / Attack Vector | MITRE ATT&CK Technique | Vulnerable State | Conditional Access Defense | Policy ID |
|---|---|---|---|---|
| **Foreign Credential Stuffing** | T1110.004 (Credential Stuffing) | Logins allowed from anywhere globally | Restrict access to designated operational geographic regions. | **CAP-001** |
| **Privileged Account Takeover** | T1078.004 (Cloud Accounts) | Admin accounts protected by password only | Enforce mandatory phishing-resistant / strong MFA across all directory roles. | **CAP-002** |
| **Impossible Travel / Risky Sign-ins** | T1078 (Valid Accounts) | Anomalous IP / session tokens allowed | Entra ID Protection ML flags anomaly and triggers real-time step-up MFA. | **CAP-003** |
| **Legacy Authentication Exploits** | T1110.001 (Password Guessing via Basic Auth) | POP3/IMAP4/SMTP bypass MFA | Absolute block on all legacy protocol endpoints unable to challenge MFA. | **CAP-004** |
| **Session Cookie & Token Replay** | T1539 (Steal Web Session Cookie) | Persistent browser tokens valid indefinitely | Limit token lifetime to 8 hours and disable persistent cookies for admins/contractors. | **CAP-005** |

---

## 3. Deep-Dive Threat Scenarios

### Threat 1: Automated Password Spray from Foreign Infrastructure
- **Scenario:** An adversary running botnets in unsupported jurisdictions attempts continuous password spray attacks against corporate UPNs.
- **Vulnerability:** Standard cloud apps evaluate credentials globally regardless of geographic relevance.
- **Mitigation (CAP-001):** Any authentication handshake originating outside `Allowed-Home-Country` is dropped at the pre-authentication evaluation layer without granting access.

### Threat 2: Administrator Credential Compromise via Spear-Phishing
- **Scenario:** A systems architect enters credentials into an adversary reverse-proxy phishing site. The adversary captures username and password.
- **Vulnerability:** Without MFA or role-based conditional requirements, single-factor credentials provide full admin access.
- **Mitigation (CAP-002):** Entra CA halts authentication and demands second-factor validation (FIDO2 / Microsoft Authenticator number matching).

### Threat 3: Basic Auth MFA Bypass (Legacy Protocols)
- **Scenario:** An attacker discovers that user accounts have MFA enabled on web portals, but legacy protocols (e.g., POP3, IMAP, or old Exchange ActiveSync) are still exposed.
- **Vulnerability:** Legacy authentication protocols do not support interactive MFA challenges, allowing attackers to authenticate with just a compromised password.
- **Mitigation (CAP-004):** Legacy authentication client app scopes are globally blocked, eliminating the legacy protocol attack surface completely.

### Threat 4: Stolen Session Cookie on Contractor / Shared Device
- **Scenario:** An external contractor accesses corporate systems on a non-compliant laptop. Malware dumps the browser process memory and extracts the Entra ID Primary Refresh Token (PRT) or browser session cookies.
- **Vulnerability:** Default session tokens stay valid for up to 90 days if persistent browser sessions are checked.
- **Mitigation (CAP-005):** Strict 8-hour session frequency and `Never persistent` session controls force token expiry, dramatically shrinking the window of opportunity for token replay.
