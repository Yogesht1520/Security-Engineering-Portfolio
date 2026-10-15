# Hybrid Enterprise Identity & Conditional Access Architecture

```mermaid
flowchart TB
    %% SECTION 1: CONCEPTUAL ON-PREMISES (Reference Architecture)
    subgraph OnPrem["[CONCEPTUAL ARCHITECTURE] On-Premises Infrastructure"]
        AD[("Windows Server AD DS\n(corp.local)\n[Conceptual Domain]")]
        Connect["Microsoft Entra Connect Sync\n(Password Hash Sync / PTA)\n[Conceptual Agent]"]
        AD -.->|Hybrid Directory Sync| Connect
    end

    %% SECTION 2: IMPLEMENTED CLOUD ENVIRONMENT
    subgraph EntraCloud["[IMPLEMENTED ENVIRONMENT] Microsoft Entra ID Cloud Tenant"]
        direction TB
        subgraph Directory["Identity Directory & Governance"]
            Users["Cloud Identities\n(8 Synthetic Personas)"]
            Groups["Role-Based Security Groups\n- SEC-Admins\n- SEC-StandardUsers\n- SEC-Contractors"]
            BreakGlass["Emergency Break-Glass Admin\n[Strict Policy Exemption]"]
        end

        subgraph Signals["Zero Trust Real-Time Signals"]
            UserRisk["Identity Protection Engine\n(Sign-in Risk & User Risk ML)"]
            LocSignal["Named Locations / Geo-IP\n(Allowed-Home-Country vs Foreign)"]
            ClientApp["Client App Protocol\n(Modern vs Legacy POP/IMAP)"]
            DeviceCompliance["Device Trust State\n(Intune Compliant / Hybrid Joined)"]
        end

        subgraph PolicyEngine["Declarative Conditional Access Engine (Identity-as-Code)"]
            CAP1["CAP-001: Block Sign-in Outside Allowed Regions"]
            CAP2["CAP-002: Require Phishing-Resistant MFA for Privileged Roles"]
            CAP3["CAP-003: Risk-Based Step-Up MFA"]
            CAP4["CAP-004: Block Legacy Authentication Protocols"]
            CAP5["CAP-005: Privileged Session Reauthentication Policy"]
            CAP6["CAP-006: Require Compliant or Hybrid Joined Device"]
            CAP7["CAP-007: Require MFA for All Workforce Users"]
            CAP8["CAP-008: Securing Security Information Registration"]
            CAP9["CAP-009: Restrict Privileged Access to Designated Devices"]
            CAP10["CAP-010: Apply Guest and External User Access Controls"]
            CAP12["CAP-012: High User Risk Remediation & Password Change"]
        end

        subgraph Controls["Enforcement & Grant Controls"]
            GrantMFA{"Grant Control:\nRequire MFA"}
            GrantBlock{"Grant Control:\nBlock Access"}
            SessionControl{"Session Control:\nSign-in Frequency (8h)"}
        end
    end

    %% SECTION 3: AUDITING & SIEM INTEGRATION
    subgraph Telemetry["[SIEM & GOVERNANCE] Detection & Auditing Pipeline"]
        SignInLogs[("Entra Sign-in Logs\n(Interactive & Non-Interactive)")]
        AuditLogs[("Entra Audit Logs\n(Directory Changes)")]
        Sentinel[("Microsoft Sentinel / SIEM\n(Break-Glass & Brute-Force Alerts)")]
    end

    %% SECTION 4: PROTECTED CLOUD APPLICATIONS
    subgraph TargetApps["Protected Corporate Cloud Assets"]
        M365["Microsoft 365 Apps\n(Exchange, Teams, SharePoint)"]
        AzurePortal["Azure Management & Entra Admin Center"]
    end

    %% Conceptual link
    Connect -.->|Password Hash Sync (PHS)| Users

    %% Signal evaluation flow
    Users --> Groups
    Groups --> Signals
    Signals --> PolicyEngine

    %% Policy Decisions
    PolicyEngine -->|Foreign IP / Legacy Protocol| GrantBlock
    PolicyEngine -->|Privileged Role / High Risk| GrantMFA
    PolicyEngine -->|Privileged User Session| SessionControl

    %% Outcomes
    GrantBlock -->|Pre-Auth Termination| SignInLogs
    GrantMFA -->|Challenge Satisfied| TargetApps
    SessionControl --> TargetApps

    %% Telemetry Stream
    SignInLogs --> Sentinel
    AuditLogs --> Sentinel
    BreakGlass -.->|Any Sign-in Trigger| Sentinel
```
