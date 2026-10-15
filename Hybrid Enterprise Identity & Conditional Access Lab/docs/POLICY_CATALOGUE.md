# Enterprise Conditional Access Policy Catalogue

## 1. Executive Summary & Policy Matrix

> **Staging & Governance Standard:** All policies follow strict enterprise change governance:
> 1. `Report-only` (`enabledForReportingButNotEnforced`): Continuous telemetry gathering, impact assessment, and zero user disruption.
> 2. `Simulated`: Deterministic validation via Entra ID What-If evaluation engine.
> 3. `Controlled Pilot`: Progressive enforcement on non-critical test groups.
> 4. `Enforced`: Production enforcement backed by automated rollback snapshots.

| Policy ID | Policy Name | Target Scope | Conditions / Signals | Grant / Session Control | Primary Threat Mitigated | Deployment State |
|---|---|---|---|---|---|---|
| **CAP-001** | Block Sign-in Outside Allowed Regions | All Users (Excl: `SEC-BreakGlass-Exclusion`) | Location: All locations, Exclude Trusted Countries | **Block Access** | Foreign credential-stuffing, adversary botnets (T1110.004) | **Report-only** (Simulated in What-If) |
| **CAP-002** | Require Phishing-Resistant MFA for Admins | Directory Roles & `SEC-Admins` (Excl: `SEC-BreakGlass-Exclusion`) | All cloud apps, Any device | **Grant: Phishing-Resistant MFA (FIDO2 / WHfB)** | AiTM phishing, session hijack, credential replay (T1078.004) | **Report-only / Pilot** (Verified) |
| **CAP-003** | Risk-Based Step-Up MFA | All Users (Excl: `SEC-BreakGlass-Exclusion`) | Sign-in risk: Medium & High (Entra ID Protection) | **Grant: Require MFA** | Anomalous sign-in tokens, impossible travel (T1078) | **Report-only** (Telemetry Audited) |
| **CAP-004** | Block Legacy Authentication Protocols | All Users (Excl: `SEC-BreakGlass-Exclusion`) | Client apps: Exchange ActiveSync, Other legacy clients | **Block Access** | Basic auth spray, lack of MFA support (T1110.001) | **Report-only** (Simulated in What-If) |
| **CAP-005** | Privileged Session Reauthentication | `SEC-Admins` & `SEC-Contractors` | Cloud apps: All | **Session: Sign-in frequency (8 hours), Never Persistent** | Session hijacking, stolen cookie replay (T1539) | **Report-only** (Telemetry Audited) |
| **CAP-006** | Require Compliant or Hybrid Joined Device | `SEC-StandardUsers` & `SEC-Admins` (Excl: `SEC-BreakGlass-Exclusion`) | Device Platform: Windows, macOS | **Grant: Compliant Device OR Hybrid Entra Joined** | Unmanaged / compromised BYOD access (T1078) | **Report-only** (Staged) |
| **CAP-007** | Require MFA for All Workforce Users | All Users (Excl: `SEC-BreakGlass-Exclusion`) | All cloud apps | **Grant: Require MFA** | Single-factor password spraying across employee base (T1110) | **Report-only** (Baseline) |
| **CAP-008** | Securing Security Info Registration | All Users (Excl: `SEC-BreakGlass-Exclusion`) | User Action: Register security info, Untrusted Location | **Block Access** | Attacker registering malicious MFA methods post-compromise (T1098.005) | **Report-only** (Baseline) |
| **CAP-009** | Restrict Privileged Access to Designated Devices | `SEC-Admins` (Excl: `SEC-BreakGlass-Exclusion`) | Filter for devices: Non-compliant endpoints | **Block Access** | Accessing sensitive tenant administration from personal hardware (T1078.004) | **Report-only** (Baseline) |
| **CAP-010** | Guest and External User Access Controls | `GuestsOrExternalUsers` | All cloud apps | **Grant: Require MFA; Session: 4h Re-auth** | Unmonitored B2B collaborator account takeover (T1078.001) | **Report-only** (Baseline) |
| **CAP-012** | High User Risk Remediation & Password Change | All Users (Excl: `SEC-BreakGlass-Exclusion`) | User Risk = High (Entra ID Protection) | **Grant: Require MFA AND Password Change** | Leaked credentials sold on dark web, persistent breach (T1078) | **Report-only** (Baseline) |

---

## 2. Policy Specifications

### CAP-001: Block Sign-in Outside Allowed Regions
- **Assignment:** All Users
- **Exclusion:** Group `SEC-BreakGlass-Exclusion` (Dual Emergency Accounts)
- **Target Resources:** All cloud apps
- **Conditions:**
  - Network / Locations: Include Any Location, Exclude Trusted / Home Country Named Location (`Allowed-Home-Country-Id`)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Credential stuffing attacks originated from foreign botnets and non-operational jurisdictions (MITRE ATT&CK T1110.004).
- **Deployment State:** Deployed in **Report-only** mode; verified via What-If simulation engine.

### CAP-002: Require Phishing-Resistant MFA for Privileged Roles
- **Assignment:** Directory Roles (`Global Administrator`, `Privileged Role Administrator`, `Security Administrator`, `Conditional Access Administrator`, `User Administrator`) and `SEC-Admins` group
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** All cloud apps
- **Conditions:** Any platform, any network
- **Grant Controls:** Require Authentication Strength (`00000000-0000-0000-0000-000000000004` — Phishing-resistant MFA: FIDO2 Security Keys, Windows Hello for Business).
- **Real-World Threat Mitigated:** Adversary-in-the-Middle (AiTM) reverse-proxy phishing kits (e.g. Evilginx) that capture session cookies and bypass standard SMS/Push MFA (MITRE ATT&CK T1078.004, T1556).
- **Deployment State:** **Report-only** baseline; tested via interactive challenge.

### CAP-003: Require MFA for Risky Sign-ins
- **Assignment:** All Users
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** All cloud apps
- **Conditions:** Sign-in risk level = Medium, High (Entra ID Protection ML engine)
- **Grant Controls:** Require multifactor authentication
- **Real-World Threat Mitigated:** Real-time token anomalies, anonymous IP usage, and impossible travel detected by machine learning (MITRE ATT&CK T1078).
- **Deployment State:** Deployed in **Report-only** mode.

### CAP-004: Block Legacy Authentication Protocols
- **Assignment:** All Users
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** All cloud apps
- **Conditions:** Client apps = Exchange ActiveSync clients, Other clients (POP3, IMAP4, SMTP, MAPI)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Legacy protocols cannot enforce modern MFA prompts, making them the primary target for automated credential stuffing and password sprays (MITRE ATT&CK T1110.001).
- **Deployment State:** Deployed in **Report-only** mode; verified via What-If simulation engine.

### CAP-005: Privileged Session Reauthentication Policy
- **Assignment:** Groups: `SEC-Admins`, `SEC-Contractors`
- **Exclusion:** None (Session controls apply to all interactive administrator sessions)
- **Target Resources:** All cloud apps
- **Session Controls:** 
  - Sign-in frequency: `8 Hours`
  - Persistent browser session: `Never persistent`
- **Technical Clarification:** Sign-in frequency controls the periodic re-prompt interval for interactive web applications; it is not an absolute hardware token lifetime. Combined with non-persistent browser cookies, it ensures session tokens cannot survive browser closure on shared endpoints (MITRE ATT&CK T1539).
- **Deployment State:** Deployed in **Report-only** mode; verified in Entra sign-in telemetry logs (`Report-only: Success`).

### CAP-006: Require Compliant or Hybrid Joined Device
- **Assignment:** Groups: `SEC-Admins`, `SEC-StandardUsers`
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** All cloud apps
- **Conditions:** Device Platforms = Windows, macOS
- **Grant Controls:** Require device to be marked as compliant OR Require Microsoft Entra hybrid joined device
- **Trust Model Note:** Uses `operator: OR` allowing either corporate Intune MDM compliance or on-premises domain-joined hybrid status to satisfy the grant.
- **Deployment State:** Deployed in **Report-only** mode to audit unmanaged endpoint footprint before policy enforcement.

### CAP-007: Require MFA for All Workforce Users
- **Assignment:** All Users
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** All cloud apps
- **Conditions:** All platforms, all networks
- **Grant Controls:** Require multifactor authentication
- **Real-World Threat Mitigated:** Establishes universal baseline protection against credential compromise across the entire employee directory (MITRE ATT&CK T1110).
- **Deployment State:** Deployed in **Report-only** mode.

### CAP-008: Securing Security Information Registration
- **Assignment:** All Users
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** User Action = `urn:user:registersecurityinfo`
- **Conditions:** Location: Any location, Exclude: Trusted Named Locations (`Allowed-Home-Country-Id`)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Prevents an adversary with compromised passwords from registering rogue Authenticator apps or FIDO2 keys from foreign infrastructure (MITRE ATT&CK T1098.005).
- **Deployment State:** Deployed in **Report-only** mode.

### CAP-009: Restrict Privileged Access to Designated Devices
- **Assignment:** Group `SEC-Admins`
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** All cloud apps
- **Conditions:** Filter for devices: Exclude compliant devices (`device.isCompliant -eq True`)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Enforces Privileged Access Workstation (PAW) discipline, blocking administrators from accessing the Entra Admin Center from personal BYOD devices (MITRE ATT&CK T1078.004).
- **Deployment State:** Deployed in **Report-only** mode.

### CAP-010: Apply Guest and External User Access Controls
- **Assignment:** Users: `GuestsOrExternalUsers`
- **Exclusion:** None
- **Target Resources:** All cloud apps
- **Grant Controls:** Require multifactor authentication
- **Session Controls:** Sign-in frequency: `4 Hours`, Persistent browser session: `Never persistent`
- **Real-World Threat Mitigated:** Isolates external vendor and partner access with tighter session boundaries and mandatory multi-factor validation (MITRE ATT&CK T1078.001).
- **Deployment State:** Deployed in **Report-only** mode.

### CAP-012: High User Risk Remediation and Password Change
- **Assignment:** All Users
- **Exclusion:** Group `SEC-BreakGlass-Exclusion`
- **Target Resources:** All cloud apps
- **Conditions:** User Risk Level = High (Credentials leaked on dark web / confirmed account compromise)
- **Grant Controls:** Require multifactor authentication AND Require password change (`operator: AND`)
- **Real-World Threat Mitigated:** Automatically enforces self-service remediation and invalidates compromised passwords without requiring manual SOC password resets (MITRE ATT&CK T1078).
- **Deployment State:** Deployed in **Report-only** mode.
