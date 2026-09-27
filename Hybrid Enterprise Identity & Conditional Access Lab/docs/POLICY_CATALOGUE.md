# Enterprise Conditional Access Policy Catalogue

## 1. Executive Summary & Policy Matrix

| Policy ID | Policy Name | Target Scope | Conditions / Signals | Grant / Session Control | Primary Threat Mitigated | State |
|---|---|---|---|---|---|---|
| **CAP-001** | Block Sign-in Outside Allowed Regions | All Users (Excl. Break-Glass) | Location: All locations, Exclude Trusted Countries | **Block Access** | Foreign credential-stuffing, password sprays from adversary infrastructure | Report-only |
| **CAP-002** | Require Phishing-Resistant/Strong MFA for Admins | Directory Roles (All Admin roles) | All cloud apps, Any device | **Grant: Require MFA** | Account takeover of privileged administrative assets | Report-only |
| **CAP-003** | Risk-Based Step-Up MFA | All Users | Sign-in risk: Medium & High | **Grant: Require MFA** | Anomalous sign-in tokens, credential leaks, impossible travel | Report-only |
| **CAP-004** | Block Legacy Authentication Protocols | All Users | Client apps: Exchange ActiveSync, Other legacy clients | **Block Access** | Basic auth bypass attacks, lack of MFA support in legacy protocols | Report-only |
| **CAP-005** | Privileged Session Sign-in Frequency | `SEC-Admins` & `SEC-Contractors` | Cloud apps: All / Azure Management | **Session: Sign-in frequency (8 hours)** | Persistent session hijacking, stale token replay | Report-only |

---

## 2. Policy Specifications

### CAP-001: Block Sign-in Outside Allowed Regions
- **Assignment:** All Users (Exclude: Break-glass emergency account)
- **Target Resources:** All cloud apps
- **Conditions:**
  - Network / Locations: Include Any Location, Exclude Trusted / Home Country (e.g., India / United States)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Credential stuffing attacks originated from foreign botnets and non-operational jurisdictions.
- **Enforcement Strategy:** Deploy in **Report-only** mode for 48 hours to inspect Entra sign-in logs before switching to **On**.

### CAP-002: Require Strong MFA for Administrative Roles
- **Assignment:** Directory Roles (`Global Administrator`, `Privileged Role Administrator`, `Security Administrator`, `Conditional Access Administrator`, `User Administrator`)
- **Target Resources:** All cloud apps
- **Conditions:** Any platform, any network
- **Grant Controls:** Require multifactor authentication
- **Real-World Threat Mitigated:** Privileged identity compromise leading to full tenant takeover.

### CAP-003: Require MFA for Risky Sign-ins
- **Assignment:** All Users
- **Target Resources:** All cloud apps
- **Conditions:** Sign-in risk level = Medium, High
- **Grant Controls:** Require multifactor authentication
- **Real-World Threat Mitigated:** Real-time token anomalies, anonymous IP usage, and impossible travel detected by Entra ID Protection machine learning.

### CAP-004: Block Legacy Authentication Protocols
- **Assignment:** All Users
- **Target Resources:** All cloud apps
- **Conditions:**
  - Client apps: Exchange ActiveSync clients, Other clients (POP3, IMAP4, SMTP, MAPI)
- **Grant Controls:** Block access
- **Real-World Threat Mitigated:** Legacy protocols cannot enforce MFA prompts, making them the primary target for automated credential stuffing and password sprays.

### CAP-005: Privileged Session Sign-in Frequency (8 Hours)
- **Assignment:** Groups: `SEC-Admins`, `SEC-Contractors`
- **Target Resources:** All cloud apps (or Microsoft Admin Portals)
- **Conditions:** Any
- **Session Controls:** Sign-in frequency: `8 Hours`
- **Real-World Threat Mitigated:** Prevents long-lived browser refresh tokens on untrusted or shared endpoints from retaining access indefinitely.
