# Threat Model & Conditional Access Mapping

## 1. Threat Landscape Overview

In modern enterprise architectures, the network perimeter is fluid. Identity represents the primary security boundary ("Identity is the New Perimeter"). Threat actors actively exploit identity misconfigurations via automated credential stuffing, adversary-in-the-middle phishing, rogue authentication method registration, session token theft, and legacy protocol exploitation.

This document maps our Conditional Access policies to the **MITRE ATT&CK for Cloud Matrix** and demonstrates the specific attack scenarios mitigated.

---

## 2. MITRE ATT&CK Matrix Mapping

| Threat / Attack Vector | MITRE ATT&CK Technique | Vulnerable State | Conditional Access Defense | Policy ID |
|---|---|---|---|---|
| **Foreign Credential Stuffing** | T1110.004 (Credential Stuffing) | Logins allowed from anywhere globally | Restrict access to designated operational geographic regions. | **CAP-001** |
| **Privileged Account Takeover** | T1078.004 (Cloud Accounts) | Admin accounts protected by weak/single-factor credentials | Enforce Phishing-Resistant MFA (FIDO2 / WHfB) across directory roles. | **CAP-002** |
| **Impossible Travel / Risky Sign-ins** | T1078 (Valid Accounts) | Anomalous IP / session tokens allowed | Entra ID Protection ML flags anomaly and triggers real-time step-up MFA. | **CAP-003** |
| **Legacy Authentication Exploits** | T1110.001 (Password Guessing via Basic Auth) | POP3/IMAP4/SMTP bypass MFA | Absolute block on all legacy protocol endpoints unable to challenge MFA. | **CAP-004** |
| **Session Cookie & Token Replay** | T1539 (Steal Web Session Cookie) | Persistent browser tokens valid indefinitely | Enforce 8-hour sign-in frequency and disable persistent cookies for admins/contractors. | **CAP-005** |
| **Unmanaged Endpoint Access** | T1078 (Valid Accounts) | Personal/malware-infected devices allowed | Require device to be Intune Compliant or Hybrid Azure AD Joined. | **CAP-006** |
| **Universal Workforce Spray** | T1110 (Brute Force) | Non-admin users without enforced MFA | Universal baseline MFA across all cloud apps. | **CAP-007** |
| **Rogue MFA Method Registration** | T1098.005 (Device Registration) | Attackers register rogue Authenticator from foreign IPs post-compromise | Block security info registration outside trusted named locations. | **CAP-008** |
| **Admin Login from Personal BYOD** | T1078.004 (Cloud Accounts) | Administrators accessing tenant portals from unmanaged machines | Enforce Privileged Access Workstation (PAW) discipline via device filters. | **CAP-009** |
| **Compromised Partner / Guest Login** | T1078.001 (Default Accounts) | B2B external collaborators lack MFA and session bounds | Enforce MFA and aggressive 4-hour reauthentication on guest users. | **CAP-010** |
| **Breached / Dark Web Credentials** | T1078 (Valid Accounts) | Passwords discovered in dark-web breach dumps | Automatically enforce MFA and password change on high user risk. | **CAP-012** |

---

## 3. Deep-Dive Threat Scenarios

### Threat 1: Automated Password Spray from Foreign Infrastructure
- **Scenario:** An adversary running botnets in unsupported jurisdictions attempts continuous password spray attacks against corporate UPNs.
- **Vulnerability:** Standard cloud apps evaluate credentials globally regardless of geographic relevance.
- **Mitigation (CAP-001):** Any authentication handshake originating outside `Allowed-Home-Country-Id` is dropped at the pre-authentication evaluation layer without granting access.

### Threat 2: Adversary-in-the-Middle (AiTM) Reverse Proxy Phishing
- **Scenario:** An adversary deploys reverse-proxy phishing kits (e.g., Evilginx) that proxy legitimate Microsoft login prompts, harvesting credentials and session cookies simultaneously.
- **Vulnerability:** Standard SMS and basic OTP push notifications are vulnerable to real-time relaying.
- **Mitigation (CAP-002):** CAP-002 enforces **Phishing-Resistant MFA** (FIDO2 Security Keys / Windows Hello for Business) via Microsoft Entra Authentication Strength. FIDO2 binds the authentication cryptographic handshake directly to the TLS origin domain, rendering reverse-proxy phishing completely ineffective.

### Threat 3: Basic Auth MFA Bypass (Legacy Protocols)
- **Scenario:** An attacker discovers that user accounts have MFA enabled on web portals, but legacy protocols (e.g., POP3, IMAP, or old Exchange ActiveSync) are still exposed.
- **Vulnerability:** Legacy authentication protocols do not support interactive MFA challenges, allowing attackers to authenticate with just a compromised password.
- **Mitigation (CAP-004):** Legacy authentication client app scopes are globally blocked, eliminating the legacy protocol attack surface completely.

### Threat 4: Stolen Session Cookie on Contractor / Shared Device
- **Scenario:** An external contractor accesses corporate systems on an unmanaged laptop. Malware dumps browser memory and extracts the Entra ID Primary Refresh Token (PRT) or browser session cookies.
- **Vulnerability:** Default session tokens stay valid for up to 90 days if persistent browser sessions are checked.
- **Mitigation (CAP-005):** Strict 8-hour sign-in frequency and `Never persistent` browser session controls force periodic reauthentication, dramatically shrinking the window of opportunity for token replay.

### Threat 5: Rogue Authentication Method Registration (Persistence)
- **Scenario:** An adversary compromises a user password during off-hours and attempts to register their own phone number or Microsoft Authenticator app on `mysignins.microsoft.com`.
- **Vulnerability:** By default, users can register MFA methods from any internet IP address unless restricted.
- **Mitigation (CAP-008):** Conditional Access intercepts the `urn:user:registersecurityinfo` user action and blocks registration attempts originating outside corporate trusted named locations.

### Threat 6: High User Risk Credential Exposure
- **Scenario:** Threat intelligence detects corporate user credentials circulated on illicit dark web forums. Entra ID Protection flags the identity as `User Risk = High`.
- **Vulnerability:** Without automated risk policies, the attacker can use the valid credentials until a manual helpdesk ticket is raised.
- **Mitigation (CAP-012):** Entra ID Protection dynamically invokes CAP-012, requiring the user to complete multi-factor authentication AND perform a secure password change in a single flow, instantly evicting the compromised password.
