# Hybrid Enterprise Identity & Conditional Access Architecture

```mermaid
flowchart TB
    subgraph OnPrem["On-Premises Infrastructure (Conceptual Architecture)"]
        AD[("Windows Server AD DS\n(corp.local)")]
        Connect["Microsoft Entra Connect Sync\n(Password Hash Sync / PTA)"]
        AD -->|Hybrid Directory Sync| Connect
    end

    subgraph EntraCloud["Microsoft Entra ID Tenant (quickheal327.onmicrosoft.com)"]
        direction TB
        subgraph Directory["Identity Directory & Governance"]
            Users["Identities / Cloud Accounts"]
            Groups["Security Groups\n- SEC-Admins\n- SEC-StandardUsers\n- SEC-Contractors"]
            PIM["Privileged Identity Management (PIM)\n& Entra Roles"]
        end

        subgraph Signals["Signal Assessment Engine"]
            UserRisk["User & Sign-in Risk\n(Entra ID Protection)"]
            DeviceSignal["Device Platform & Compliance\n(Intune / Hybrid Joined)"]
            LocSignal["Named Locations / Geo-IP\n(Trusted vs Untrusted Countries)"]
            ClientApp["Client App Type\n(Modern Auth vs Legacy Protocols)"]
        end

        subgraph PolicyEngine["Conditional Access Engine (Zero Trust Decision Point)"]
            CAP1["CAP-001: Block Foreign Geo-Locations"]
            CAP2["CAP-002: Require MFA for Admin Roles"]
            CAP3["CAP-003: Require MFA for Risky Sign-ins"]
            CAP4["CAP-004: Block Legacy Authentication"]
            CAP5["CAP-005: 8-Hour Session Lifetime for Privileged Roles"]
        end

        subgraph Controls["Enforcement & Grant Controls"]
            GrantMFA{"Enforce MFA\n(MS Authenticator / FIDO2)"}
            GrantBlock{"Block Access\n(Immediate Deny)"}
            SessionControl{"Session Control\n(Sign-in Frequency)"}
        end
    end

    subgraph TargetApps["Protected Enterprise Applications & Cloud Resources"]
        M365["Microsoft 365 Services\n(Exchange, Teams, SharePoint)"]
        AzurePortal["Azure Management & Entra Portal"]
        SaaS["Enterprise SaaS & Custom Apps"]
    end

    %% Connections
    Connect -.->|Password Hash Sync (PHS)| Users
    Users --> Groups
    Groups --> Signals
    Signals --> PolicyEngine

    PolicyEngine -->|Deny foreign / legacy| GrantBlock
    PolicyEngine -->|Admin / Risky sign-in| GrantMFA
    PolicyEngine -->|Session limits| SessionControl

    GrantBlock -->|Deny| Denied[("Access Denied Logged")]
    GrantMFA -->|Satisfied| TargetApps
    SessionControl --> TargetApps
```
