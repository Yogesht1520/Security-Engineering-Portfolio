# Enterprise Hybrid Identity & Conditional Access Security Lab

> **Aligned with:** Microsoft SC-300 (Identity & Access Administrator) & NIST Zero Trust Architecture (SP 800-207)  
> **Environment:** Microsoft Entra ID (P2) Cloud Tenant *(Sanitized Lab Tenant)*  
> **Methodology:** Declarative Identity-as-Code (IaC) & Continuous Security Staging  

---

## 1. Executive Summary

This project delivers an enterprise-grade **Zero Trust Identity and Access Management (IAM)** framework engineered in **Microsoft Entra ID (formerly Azure AD)**. Moving away from perimeter-centric security, this architecture positions **Identity as the primary control plane**.

Key engineering highlights of this implementation:
- **Declarative Identity-as-Code (IaC):** Conditional Access policies managed as version-controlled JSON objects in [`policies/`](./policies/) and deployed via automated Microsoft Graph SDK scripts.
- **Enterprise Staging Methodology:** Strict progression from `Report-only` auditing to mathematical simulation, culminating in live zero-trust enforcement.
- **Automated Lifecycle Management:** PowerShell-driven Joiner/Mover/Leaver (JML) automation, including instant token revocation and group de-provisioning.
- **MITRE ATT&CK Mapping:** Targeted defenses against credential stuffing, legacy protocol bypasses, privileged account takeover, and session token theft.

---

## 2. Architecture & Boundary Model

> **Boundary Callout:** In compliance with enterprise documentation standards, components are explicitly partitioned between **[Implemented Cloud Environment]** (built and tested in Entra ID) and **[Conceptual Architecture]** (reference hybrid directory sync topology).

```mermaid
flowchart TB
    %% CONCEPTUAL SECTION
    subgraph OnPrem["[CONCEPTUAL ARCHITECTURE] On-Premises Active Directory"]
        AD[("Windows Server AD DS\n(corp.local)\n[Reference Architecture]")]
        Connect["Microsoft Entra Connect Sync\n(Password Hash Sync / PTA)\n[Conceptual Sync Agent]"]
        AD -.->|Hybrid Directory Sync| Connect
    end

    %% IMPLEMENTED SECTION
    subgraph EntraCloud["[IMPLEMENTED ENVIRONMENT] Microsoft Entra ID Cloud Tenant"]
        direction TB
        subgraph Directory["Identity Directory & Governance"]
            Users["Cloud Identities\n(8 Synthetic Personas)"]
            Groups["Role-Based Security Groups\n- SEC-Admins\n- SEC-StandardUsers\n- SEC-Contractors"]
            BreakGlass["Emergency Break-Glass Account\n(Strict Exclusion & Alerting)"]
        end

        subgraph Signals["Zero Trust Real-Time Signal Assessment"]
            GeoIP["Named Locations / Geo-IP\n(Allowed-Home-Country vs Foreign)"]
            RiskEngine["Entra ID Protection\n(Sign-in & User Risk ML)"]
            ClientType["Client App Type\n(Modern Auth vs Legacy POP/IMAP)"]
            DeviceTrust["Device Trust State\n(Intune Compliant / Hybrid Joined)"]
        end

        subgraph PolicyEngine["Declarative Conditional Access Engine (Identity-as-Code)"]
            CAP1["CAP-001: Block Foreign Geo-Locations"]
            CAP2["CAP-002: Require MFA for Admin Roles"]
            CAP3["CAP-003: Require MFA for Risky Sign-ins"]
            CAP4["CAP-004: Block Legacy Authentication"]
            CAP5["CAP-005: 8-Hour Session Lifetime (Admins/Vendors)"]
            CAP6["CAP-006: Require Compliant / Hybrid Device"]
        end

        subgraph Controls["Enforcement & Session Controls"]
            GrantMFA{"Grant: Require MFA\n(Number Matching / Authenticator)"}
            GrantBlock{"Grant: Block Access\n(Immediate Deny)"}
            SessionLimits{"Session Control:\nSign-in Frequency (8h)"}
        end
    end

    %% SIEM SECTION
    subgraph Telemetry["[SIEM & GOVERNANCE] Audit & Telemetry Pipeline"]
        SignInLogs[("Entra Sign-in Logs\n(Interactive & Report-Only)")]
        Sentinel[("Microsoft Sentinel / SIEM\n(Break-Glass & Brute-Force Detection)")]
    end

    %% Protected Assets
    subgraph TargetApps["Protected Corporate Cloud Resources"]
        M365Apps["Microsoft 365 Services\n(Exchange, Teams, SharePoint)"]
        AzureMgmt["Azure Management & Entra Admin Center"]
    end

    %% Connectors
    Connect -.->|Password Hash Sync (PHS)| Users
    Users --> Groups
    Groups --> Signals
    Signals --> PolicyEngine

    PolicyEngine -->|Foreign Geo / Legacy Auth| GrantBlock
    PolicyEngine -->|Privileged Role / High Risk| GrantMFA
    PolicyEngine -->|Privileged User Session| SessionLimits

    GrantBlock -->|Denied Pre-Auth| SignInLogs
    GrantMFA -->|Challenge Satisfied| TargetApps
    SessionLimits --> TargetApps

    SignInLogs --> Sentinel
    BreakGlass -.->|Any Sign-in Trigger (P0 Alert)| Sentinel
```

---

## 3. Conditional Access Policy Catalogue

All policies are synchronized with the declarative templates in [`policies/`](./policies/):

| Policy ID | Policy Name | Scope / Target | Conditions & Signals | Enforcement Control | Staging Lifecycle State |
|---|---|---|---|---|---|
| **CAP-001** | Block Sign-in Outside Allowed Regions | All Users (Excl. Break-Glass) | Location: Any, Excl. `Allowed-Home-Country` | **Block access** | **Report-only** (Validated in What-If) |
| **CAP-002** | Require Multi-Factor Authentication for Admins | Directory Roles & `SEC-Admins` | All cloud apps, Any device | **Grant: Require MFA** | **Enforced (On)** (Live Challenge Verified) |
| **CAP-003** | Risk-Based Step-Up MFA | All Users (Excl. Break-Glass) | Sign-in risk: Medium & High | **Grant: Require MFA** | **Report-only** (Telemetry Audited) |
| **CAP-004** | Block Legacy Authentication | All Users (Excl. Break-Glass) | Client apps: POP3, IMAP, ActiveSync | **Block access** | **Report-only** (Validated in What-If) |
| **CAP-005** | Privileged Session Frequency (8h) | `SEC-Admins`, `SEC-Contractors` | All cloud apps | **Session: 8hr Re-auth, Never persistent** | **Report-only** (Telemetry Audited) |
| **CAP-006** | Require Compliant or Hybrid Joined Device | `SEC-Admins`, `SEC-StandardUsers` | Device platforms: Windows, macOS | **Grant: Require Compliant or Hybrid Joined** | **Report-only** (Staged in Entra ID) |

---

## 4. Identity-as-Code (IaC) & Automation Engine

### 4.1 Declarative Policy Pipeline
Rather than relying solely on manual portal changes, policies are defined declaratively as JSON schemas in [`policies/`](./policies/) and deployed using [`scripts/deploy_ca_policies.ps1`](./scripts/deploy_ca_policies.ps1):

```text
policies/
├── CAP-001-location.json            # Geo-blocking rule definition
├── CAP-002-admin-mfa.json           # Privileged role MFA definition
├── CAP-003-risk-mfa.json            # Machine-learning risk trigger
├── CAP-004-legacy-auth.json         # Protocol deprecation rule
├── CAP-005-session.json             # 8-hr sign-in frequency & cookie control
└── CAP-006-device-compliance.json   # Endpoint health verification
```

```powershell
# Validate JSON schemas in CI/CD pipeline without pushing changes:
.\scripts\deploy_ca_policies.ps1 -ValidateOnly

# Deploy or update policies idempotently to Entra ID:
.\scripts\deploy_ca_policies.ps1
```

### 4.2 Automated Lifecycle Management (JML)
- **User Provisioning (`scripts/seed_users.ps1`):** Provisions 3 security groups and 8 synthetic personas using least-privilege Graph scopes (`User.ReadWrite.All`, `Group.ReadWrite.All`), eliminating hardcoded passwords and interactive console leakage.
- **Automated Leaver Workflow (`scripts/offboard_user.ps1`):** Automatically revokes all active OAuth tokens/browser sessions via `Revoke-MgUserSignInSession`, disables the Entra account, and strips all group memberships to prevent session hijacking.

---

## 5. Security Validation & What-If Test Matrix

### 5.1 Verification Test Matrix

| Test ID | Target Policy | Test Scenario | Evaluated Conditions | Expected Verdict | Observed Outcome | Evidence Link |
|---|---|---|---|---|---|---|
| **TEST-01** | CAP-001 | Foreign IP Login | User: `usr-jordan`, Location: `Germany` | Block Access | Access blocked pre-auth | [`02-whatif-simulation-block.png`](./screenshots/02-whatif-simulation-block.png) |
| **TEST-02** | CAP-004 | Legacy Protocol Auth | User: `usr-jordan`, Client: `Exchange ActiveSync` | Block Access | Access blocked pre-auth | [`02-whatif-simulation-block.png`](./screenshots/02-whatif-simulation-block.png) |
| **TEST-03** | CAP-005 | Privileged Session Timeout | User: `adm-alex`, Group: `SEC-Admins` | Apply 8hr sign-in frequency | Sign-in logs confirm `Report-only: Success` | [`03-signin-logs-report-only.png`](./screenshots/03-signin-logs-report-only.png) |
| **TEST-04** | CAP-002 | Enforced Admin MFA | User: `adm-alex`, Role: `SEC-Admins` | Mandatory second factor challenge | Sign-in interrupted; Authenticator required | [`04-mfa-challenge-prompt.png`](./screenshots/04-mfa-challenge-prompt.png) |
| **TEST-05** | CAP-002 | Single-Factor Log Audit | User: `adm-alex`, Single-factor attempt | Token withheld | Enforced log recorded as `Failure` | [`05-signin-log-mfa-enforced.png`](./screenshots/05-signin-log-mfa-enforced.png) |

---

## 6. Emergency Access & SIEM Monitoring Strategy

### 6.1 Break-Glass Account Design
- **Account:** `emergency-admin@<tenant-domain>`
- **Role:** Assigned `Global Administrator` role.
- **Exclusion Policy:** Explicitly excluded from all Conditional Access policies to prevent accidental lockout during policy configuration incidents.
- **Security Controls:** Secured with a 32-character physical vault-stored passphrase and dedicated hardware FIDO2 security key.

### 6.2 Break-Glass SIEM Detection Rule (KQL)
Any sign-in from the emergency account triggers an immediate **Severity: High (P0)** alert in Microsoft Sentinel / SIEM:

```kusto
SigninLogs
| where UserPrincipalName =~ "emergency-admin@quickheal327.onmicrosoft.com"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Status, DeviceDetail
```

---

## 7. Project Documentation Index

- [Architecture Diagram (Mermaid)](./diagrams/architecture.md)
- [Conditional Access Policy Specifications](./docs/POLICY_CATALOGUE.md)
- [User & Directory Governance Model](./docs/USER_GROUP_MODEL.md)
- [Threat Model & MITRE ATT&CK Mapping](./docs/THREAT_MODEL.md)
- [Reproduction & Operational Runbook](./docs/RUNBOOK.md)
- [Declarative Policy Templates](./policies/)
- [Automation & Offboarding Scripts](./scripts/)
- [Evidence Screenshot Index](./screenshots/README.md)
