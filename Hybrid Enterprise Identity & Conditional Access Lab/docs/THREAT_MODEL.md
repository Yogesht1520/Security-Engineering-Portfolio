# Threat Model & Conditional Access Mapping

## 1. Threat Landscape Overview

In modern enterprise architectures, the network perimeter is fluid. Identity represents the primary security boundary ("Identity is the New Perimeter"). Threat actors actively exploit identity misconfigurations via automated credential stuffing, phishing, session token theft, and legacy protocol exploitation.

This document maps our Conditional Access policies to the **MITRE ATT&CK for Cloud Matrix** and demonstrates the specific attack scenarios mitigated.

---

## 2. MITRE ATT&CK Matrix Mapping

| Threat / Attack Vector | MITRE ATT&CK Technique | Vulnerable State | Conditional Access Defense | Policy ID |
|---|---|---|---|---|
| **Foreign Credential Stuffing** | T1110.004 (Credential Stuffing) | Logins allowed from anywhere globally | Restrict access to designated operational geographic regions. | **CAP-001** |
| **Privileged Account Takeover** | T1078.004 (Cloud Accounts) | Admin accounts protected by password only | Enforce mandatory MFA across all directory roles. | **CAP-002** |
| **Impossible Travel / Risky Sign-ins** | T1078 (Valid Accounts) | Anomalous IP / session tokens allowed | Entra ID Protection ML flags anomaly and triggers real-time step-up MFA. | **CAP-003** |
| **Legacy Authentication Exploits** | T1110.001 (Password Guessing via Basic Auth) | POP3/IMAP4/SMTP bypass MFA | Absolute block on all legacy protocol endpoints unable to challenge MFA. | **CAP-004** |
| **Session Cookie & Token Replay** | T1539 (Steal Web Session Cookie) | Persistent browser tokens valid indefinitely | Limit token lifetime to 8 hours and disable persistent cookies for admins/contractors. | **CAP-005** |
| **Unmanaged Endpoint Access** | T1078 (Valid Accounts) | Personal/malware-infected devices allowed | Require device to be Intune Compliant or Hybrid Azure AD Joined. | **CAP-006** |
| **MFA Fatigue / Push Bombing** | T1621 (Multi-Factor Authentication Request Generation) | Simple tap-to-approve push notifications | Enforce number matching and context-rich push prompts. | Platform MFA Config |
| **Illicit OAuth Consent Grant** | T1528 (Steal Application Access Token) | Users can grant API permissions to 3rd party apps | Disable end-user consent; require Admin Consent Workflow. | Entra App Governance |

---

## 3. Deep-Dive Threat Scenarios

### Threat 1: Automated Password Spray from Foreign Infrastructure
- **Scenario:** An adversary running botnets in unsupported jurisdictions attempts continuous password spray attacks against corporate UPNs.
- **Vulnerability:** Standard cloud apps evaluate credentials globally regardless of geographic relevance.
- **Mitigation (CAP-001):** Any authentication handshake originating outside `Allowed-Home-Country` is dropped at the pre-authentication evaluation layer without granting access.

### Threat 2: Administrator Credential Compromise via Spear-Phishing
- **Scenario:** A systems architect enters credentials into an adversary phishing site. The adversary captures username and password.
- **Vulnerability:** Without MFA or role-based conditional requirements, single-factor credentials provide full admin access.
- **Mitigation (CAP-002):** Entra CA halts authentication and demands second-factor validation (Microsoft Authenticator number matching / FIDO2).

### Threat 3: Basic Auth MFA Bypass (Legacy Protocols)
- **Scenario:** An attacker discovers that user accounts have MFA enabled on web portals, but legacy protocols (e.g., POP3, IMAP, or old Exchange ActiveSync) are still exposed.
- **Vulnerability:** Legacy authentication protocols do not support interactive MFA challenges, allowing attackers to authenticate with just a compromised password.
- **Mitigation (CAP-004):** Legacy authentication client app scopes are globally blocked, eliminating the legacy protocol attack surface completely.

### Threat 4: Stolen Session Cookie on Contractor / Shared Device
- **Scenario:** An external contractor accesses corporate systems on an unmanaged laptop. Malware dumps browser memory and extracts the Entra ID Primary Refresh Token (PRT) or browser session cookies.
- **Vulnerability:** Default session tokens stay valid for up to 90 days if persistent browser sessions are checked.
- **Mitigation (CAP-005):** Strict 8-hour session frequency and `Never persistent` session controls force token expiry, dramatically shrinking the window of opportunity for token replay.

### Threat 5: Adversary-in-the-Middle (AiTM) Phishing & Session Theft
- **Scenario:** An adversary deploys reverse-proxy phishing kits (e.g., Evilginx) that proxy legitimate Microsoft login prompts, harvesting credentials and session cookies simultaneously.
- **Vulnerability:** Standard SMS and basic OTP push notifications are vulnerable to real-time relaying.
- **Defense Evolution:** CAP-002 enforces strong MFA as the baseline. For ultimate defense against AiTM, organizations upgrade CAP-002 to require **Phishing-Resistant MFA** (FIDO2 / Windows Hello for Business), binding the authentication cryptographic handshake directly to the TLS origin domain.

### Threat 6: MFA Fatigue / Push Bombing
- **Scenario:** Attackers trigger repeated mobile push notifications at 3:00 AM until an exhausted employee accidentally approves the login.
- **Mitigation:** Microsoft Entra ID enforces **Number Matching** (user must type the exact two-digit code displayed on the login screen into the Authenticator app) and geographic context display, completely neutralizing blind push approval.

### Threat 7: Illicit OAuth Consent Grant
- **Scenario:** An employee receives an email asking them to authorize an external calendar app. The app requests `Mail.ReadWrite` and `Files.ReadWrite.All` delegated permissions.
- **Vulnerability:** Unrestricted self-service application consent allows attackers to persist in the tenant without knowing the user's password.
- **Mitigation:** Tenant-wide setting configured to require **Admin Consent Workflow**, routing all third-party app consent requests to security administrators before any token is issued.
