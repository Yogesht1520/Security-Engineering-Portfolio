# Conditional Access Policy Behavioral Verification & Evaluation Matrix

> **Environment:** Microsoft Entra ID (P2) Production / Staging Tenant  
> **Evaluation Mode:** Staged in `enabledForReportingButNotEnforced` (Report-Only Baseline)  
> **Authoritative Schema:** `policies/schema/conditional-access.schema.json` (Draft-07 Compliant)  
> **Safety Exclusion:** `SEC-BreakGlass-Exclusion` strictly excluded on all broad policies.

---

## 1. Executive Policy Verification Summary

| Policy ID | Policy Name | Primary Target | Conditions | Controls | Sign-In Evaluation Result | Licensing Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CAP-001** | Block Sign-in Outside Allowed Regions | All Users | Location: Not `Allowed-Home-Country-Id` | Grant: **Block** | Foreign geolocations blocked; home country allowed | Entra ID P1 / P2 |
| **CAP-002** | Require Phishing-Resistant MFA for Privileged Roles | 6 Privileged Directory Roles | All cloud apps | Grant: **Phishing-Resistant MFA** (`...0004`) | Admins prompted for FIDO2/WHfB; SMS/TOTP rejected | Entra ID P1 / P2 |
| **CAP-003** | Risk-Based Step-Up MFA | All Users | Sign-in Risk: `medium`, `high` | Grant: **MFA** | High-risk sign-ins challenged for MFA; low-risk pass | Entra ID P2 (Identity Protection) |
| **CAP-004** | Block Legacy Authentication Protocols | All Users | Client Apps: `exchangeActiveSync`, `other` | Grant: **Block** | Legacy basic auth (POP3/IMAP/SMTP) blocked | Entra ID P1 / P2 |
| **CAP-005** | Privileged Session Reauthentication Policy | Group `SEC-Admins` | All cloud apps | Session: **1h SIF**, **Never Persistent** | Admins prompted hourly; tokens expire on tab close | Entra ID P1 / P2 |
| **CAP-006** | Require Compliant or Hybrid Joined Device | All Users | All cloud apps | Grant: **Compliant OR Hybrid Joined** | Non-managed personal machines blocked | Entra ID P1 + Intune |
| **CAP-007** | Require MFA for All Workforce Users | Group `SEC-StandardUsers` | All cloud apps | Grant: **Require MFA** | Workforce users challenged for standard MFA | Entra ID P1 / P2 |
| **CAP-008** | Securing Security Information Registration | All Users | Action: `registersecurityinfo` | Location: Not `Allowed-Home-Country-Id` &rarr; **Block** | Prevents adversary MFA registration from abroad | Entra ID P1 / P2 |
| **CAP-009** | Restrict Privileged Access to Designated Devices | Group `SEC-Admins` | Device: Not PAW (`extensionAttribute1 eq 'PAW'`) | Grant: **Block** | Only dedicated PAWs access admin consoles | Entra ID P1 / P2 + Intune |
| **CAP-010** | Apply Guest and External User Access Controls | `GuestsOrExternalUsers` | All cloud apps | Grant: **MFA**; Session: **4h SIF, Never Persistent** | B2B guests prompt for MFA; sessions bounded to 4h | Entra ID P1 / P2 (External ID) |
| **CAP-012** | High User Risk Remediation & Password Change | All Users | User Risk: `high` | Grant: **MFA AND Password Change** | Confirmed compromised identities forced to change pwd | Entra ID P2 (Identity Protection) |

---

## 2. In-Depth Behavioral Analysis & Test Telemetry

### CAP-001: Block Sign-in Outside Allowed Regions
- **Configuration:**
  - `includeUsers`: `["All"]`
  - `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `includeApplications`: `["All"]`
  - `conditions.locations`: `includeLocations = ["All"]`, `excludeLocations = ["Allowed-Home-Country-Id"]`
  - `grantControls`: `operator = "OR"`, `builtInControls = ["block"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (Authorized Geo):* User authenticating from designated trusted country &rarr; Policy evaluates `Not Applied` (Location excluded). Access allowed.
  - *Scenario 2 (Foreign / Tor Exit Node):* User authenticating from non-whitelisted IP &rarr; Policy evaluates `Report-Only: Failure (Block)`. In enforcement mode, access blocked.
- **Licensing & Dependencies:** Microsoft Entra ID P1 / P2 (Named Locations).

---

### CAP-002: Require Phishing-Resistant MFA for Privileged Roles
- **Configuration:**
  - `includeRoles`: Global Admin, Privileged Role Admin, Security Admin, CA Admin, User Admin, Helpdesk Admin.
  - `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `grantControls.authenticationStrength`: `id = "00000000-0000-0000-0000-000000000004"` (Phishing-Resistant MFA).
- **Evaluation Scenarios:**
  - *Scenario 1 (FIDO2 Hardware Key / Windows Hello for Business):* Policy evaluates `Success`. Identity satisfies phishing-resistant authentication strength.
  - *Scenario 2 (SMS / Voice / Standard Authenticator TOTP):* Policy evaluates `Failure`. User prompted to register/present FIDO2 credential.
- **Licensing & Dependencies:** Microsoft Entra ID P1 / P2 with FIDO2 / Passkey registration.

---

### CAP-003: Risk-Based Step-Up MFA
- **Configuration:**
  - `includeUsers`: `["All"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `conditions.signInRiskLevels`: `["medium", "high"]`
  - `grantControls`: `builtInControls = ["mfa"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (Impossible Travel / Anomalous Token):* Entra ID Identity Protection flags medium risk &rarr; Policy evaluates `Report-Only: Failure (MFA Required)`.
  - *Scenario 2 (Familiar Location / Low Risk):* Policy evaluates `Not Applied`.
- **Licensing & Dependencies:** Microsoft Entra ID P2 (Identity Protection Risk Engine).

---

### CAP-004: Block Legacy Authentication Protocols
- **Configuration:**
  - `includeUsers`: `["All"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `conditions.clientAppTypes`: `["exchangeActiveSync", "other"]`
  - `grantControls`: `builtInControls = ["block"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (PowerShell basic auth / IMAP client):* Basic auth protocol cannot present modern MFA claims &rarr; Evaluates `Report-Only: Failure (Block)`.
  - *Scenario 2 (Modern Browser / MSAL Desktop App):* Client presents OAuth 2.0 modern authentication &rarr; Evaluates `Not Applied`.
- **Licensing & Dependencies:** Microsoft Entra ID P1 / P2.

---

### CAP-005: Privileged Session Reauthentication Policy
- **Configuration:**
  - `includeGroups`: `["SEC-Admins"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `sessionControls.signInFrequency`: `value = 1, type = "hours", isEnabled = true`
  - `sessionControls.persistentBrowser`: `mode = "never", isEnabled = true`
- **Evaluation Scenarios:**
  - *Scenario 1 (Admin console activity):* Browser cookie marked non-persistent; PRT lifetime truncated to 60 minutes.
  - *Scenario 2 (Session expiry):* After 61 minutes, next Graph or Portal call triggers interactive reauthentication.
- **Licensing & Dependencies:** Microsoft Entra ID P1 / P2.

---

### CAP-006: Require Compliant or Hybrid Joined Device
- **Configuration:**
  - `includeUsers`: `["All"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `grantControls`: `operator = "OR", builtInControls = ["compliantDevice", "domainJoinedDevice"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (Intune Enrolled Corporate Laptop):* Device compliance status evaluated as `True` &rarr; Policy evaluates `Success`.
  - *Scenario 2 (Personal BYOD / Unregistered VM):* Device lacks compliance state in Entra ID &rarr; Evaluates `Report-Only: Failure (Device Compliance Required)`.
- **Licensing & Dependencies:** Microsoft Entra ID P1 + Microsoft Intune / Configuration Manager.

---

### CAP-007: Require MFA for All Workforce Users
- **Configuration:**
  - `includeGroups`: `["SEC-StandardUsers"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `grantControls`: `builtInControls = ["mfa"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (Standard user sign-in):* Evaluates `Success` upon completing push notification via Microsoft Authenticator.
- **Licensing & Dependencies:** Microsoft Entra ID P1 / P2.

---

### CAP-008: Securing Security Information Registration
- **Configuration:**
  - `includeUsers`: `["All"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `conditions.applications`: `includeUserActions = ["urn:user:registersecurityinfo"]`
  - `conditions.locations`: `includeLocations = ["All"]`, `excludeLocations = ["Allowed-Home-Country-Id"]`
  - `grantControls`: `builtInControls = ["block"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (Employee registering key from office / home country):* Evaluates `Not Applied`. Registration proceeds.
  - *Scenario 2 (Attacker attempting MFA enrollment from foreign VPN/proxy):* Evaluates `Report-Only: Failure (Block)`.
- **Licensing & Dependencies:** Microsoft Entra ID P1 / P2.

---

### CAP-009: Restrict Privileged Access to Designated Devices
- **Configuration:**
  - `includeGroups`: `["SEC-Admins"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `conditions.devices.deviceFilter`: `mode = "exclude", rule = "device.extensionAttribute1 -eq \"PAW\" -and device.isCompliant -eq True"`
  - `grantControls`: `builtInControls = ["block"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (Designated Hardened PAW):* Device has `extensionAttribute1 == "PAW"` and Intune `isCompliant == True` &rarr; Device filter exclusion applies &rarr; Access Allowed.
  - *Scenario 2 (Standard compliant user laptop):* Intune `isCompliant == True`, but lacks PAW extension attribute &rarr; Evaluates `Report-Only: Failure (Block)`.
  - *Scenario 3 (Unmanaged BYOD):* Evaluates `Report-Only: Failure (Block)`.
- **Licensing & Dependencies:** Microsoft Entra ID P1 / P2 + Microsoft Intune.

---

### CAP-010: Apply Guest and External User Access Controls
- **Configuration:**
  - `includeUsers`: `["GuestsOrExternalUsers"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `grantControls`: `builtInControls = ["mfa"]`
  - `sessionControls`: `signInFrequency = 4 Hours`, `persistentBrowser = "never"`
- **Evaluation Scenarios:**
  - *Scenario 1 (B2B guest sign-in):* Prompts for cross-tenant or local MFA; session restricted to non-persistent 4-hour window.
- **Licensing & Dependencies:** Microsoft Entra External ID / Entra ID P1 / P2.

---

### CAP-012: High User Risk Remediation and Password Change
- **Configuration:**
  - `includeUsers`: `["All"]`, `excludeGroups`: `["SEC-BreakGlass-Exclusion"]`
  - `conditions.userRiskLevels`: `["high"]`
  - `grantControls`: `operator = "AND", builtInControls = ["mfa", "passwordChange"]`
- **Evaluation Scenarios:**
  - *Scenario 1 (Leaked credentials detected by Microsoft Threat Intelligence):* User risk marked High &rarr; User prompted to perform MFA AND immediately reset password.
- **Licensing & Dependencies:** Microsoft Entra ID P2 (Identity Protection).
