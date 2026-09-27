# Enterprise Conditional Access Policy Catalogue

## 1. Executive Summary & Policy Matrix

> **Staging Methodology:** All policies follow an enterprise lifecycle:
> 1. `Report-only` (Telemetry gathering & impact assessment in Sign-in logs)
> 2. `Simulated` (Mathematical validation via Entra ID What-If engine)
> 3. `Enforced (On)` (Production enforcement post-validation)

| Policy ID | Policy Name | Target Scope | Conditions / Signals | Grant / Session Control | Primary Threat Mitigated | Staging Lifecycle State |
|---|---|---|---|---|---|---|
| **CAP-001** | Block Sign-in Outside Allowed Regions | All Users (Excl. Break-Glass) | Location: All locations, Exclude Trusted Countries | **Block Access** | Foreign credential-stuffing, password sprays from adversary infrastructure | **Report-only** (Simulated in What-If) |
| **CAP-002** | Require Multi-Factor Authentication for Admins | Directory Roles & `SEC-Admins` (Excl. Break-Glass) | All cloud apps, Any device | **Grant: Require MFA** *(Standard MFA Grant Control)* | Account takeover of privileged administrative assets | **Enforced (On)** (Live Verified) |
| **CAP-003** | Risk-Based Step-Up MFA | All Users (Excl. Break-Glass) | Sign-in risk: Medium & High | **Grant: Require MFA** | Anomalous sign-in tokens, credential leaks, impossible travel | **Report-only** (Telemetry Audited) |
| **CAP-004** | Block Legacy Authentication Protocols | All Users (Excl. Break-Glass) | Client apps: Exchange ActiveSync, Other legacy clients | **Block Access** | Basic auth bypass attacks, lack of MFA support in legacy protocols | **Report-only** (Simulated in What-If) |
| **CAP-005** | Privileged Session Sign-in Frequency | `SEC-Admins` & `SEC-Contractors` | Cloud apps: All / Azure Management | **Session: Sign-in frequency (8 hours), Never Persistent** | Persistent session hijacking, stale token replay | **Report-only** (Telemetry Audited) |
| **CAP-006** | Require Compliant or Hybrid Joined Device | `SEC-StandardUsers` & `SEC-Admins` | Device Platform: Windows, macOS | **Grant: Require Device to be marked as Compliant OR Hybrid Azure AD Joined** | Unmanaged / BYOD device compromise, untrusted endpoint access | **Report-only** (Staged in Entra ID) |

---

## 2. Policy Specifications

### CAP-001: Block Sign-in Outside Allowed Regions
- **Assignment:** All Users (Exclude: Break-glass emergency account)
- **Target Resources:** All cloud apps
- **Conditions:**
  - Network / Locations: Include Any Location, Exclude Trusted / Home Country Named Location (`Allowed-Home-Country`)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Credential stuffing attacks originated from foreign botnets and non-operational jurisdictions (MITRE ATT&CK T1110.004).
- **Staging State:** Deployed in **Report-only** mode; verified via What-If simulation engine.

### CAP-002: Require Multi-Factor Authentication for Administrative Roles
- **Assignment:** Directory Roles (`Global Administrator`, `Privileged Role Administrator`, `Security Administrator`, `Conditional Access Administrator`, `User Administrator`) and `SEC-Admins` group (Exclude: Break-glass emergency account)
- **Target Resources:** All cloud apps
- **Conditions:** Any platform, any network
- **Grant Controls:** Require multifactor authentication
- **Authentication Strength Note:** Uses standard Entra ID MFA Grant Control (number matching / Authenticator / FIDO2). Upgrading to strictly *Phishing-Resistant MFA* requires creating an Authentication Strength policy enforcing FIDO2/Windows Hello for Business exclusively.
- **Real-World Threat Mitigated:** Privileged identity compromise leading to full tenant takeover (MITRE ATT&CK T1078.004).
- **Staging State:** **Enforced (On)**; verified live via interactive login challenge on `adm-alex`.

### CAP-003: Require MFA for Risky Sign-ins
- **Assignment:** All Users (Exclude: Break-glass emergency account)
- **Target Resources:** All cloud apps
- **Conditions:** Sign-in risk level = Medium, High (Entra ID Protection ML engine)
- **Grant Controls:** Require multifactor authentication
- **Real-World Threat Mitigated:** Real-time token anomalies, anonymous IP usage, and impossible travel detected by machine learning (MITRE ATT&CK T1078).
- **Staging State:** Deployed in **Report-only** mode.

### CAP-004: Block Legacy Authentication Protocols
- **Assignment:** All Users (Exclude: Break-glass emergency account)
- **Target Resources:** All cloud apps
- **Conditions:**
  - Client apps: Exchange ActiveSync clients, Other clients (POP3, IMAP4, SMTP, MAPI)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Legacy protocols cannot enforce MFA prompts, making them the primary target for automated credential stuffing and password sprays (MITRE ATT&CK T1110.001).
- **Staging State:** Deployed in **Report-only** mode; verified via What-If simulation engine.

### CAP-005: Privileged Session Sign-in Frequency (8 Hours)
- **Assignment:** Groups: `SEC-Admins`, `SEC-Contractors`
- **Target Resources:** All cloud apps
- **Conditions:** Any
- **Session Controls:** 
  - Sign-in frequency: `8 Hours`
  - Persistent browser session: `Never persistent`
- **Real-World Threat Mitigated:** Prevents long-lived browser refresh tokens on untrusted or shared endpoints from retaining access indefinitely (MITRE ATT&CK T1539).
- **Staging State:** Deployed in **Report-only** mode; verified in Entra sign-in telemetry logs (`Report-only: Success`).

---

## 3. Future Architectural Roadmap (Phase 6 Stretch Goals)

### Future Policy: CAP-006 — Require Compliant or Hybrid Joined Device
- **Prerequisite:** Microsoft Intune MDM enrollment and on-premises Active Directory hybrid join sync.
- **Intent:** Restricts access to managed, healthy endpoints, blocking all personal / BYOD devices.
- **Grant Control:** `Require device to be marked as compliant` OR `Require Microsoft Entra hybrid joined device`.
