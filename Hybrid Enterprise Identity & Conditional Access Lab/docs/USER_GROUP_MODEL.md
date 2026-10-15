# Enterprise Identity & Access Management Model

## 1. Directory Overview

| Property | Value | Notes |
|---|---|---|
| **Identity Platform** | Microsoft Entra ID (P2 Active / Trial) | Enterprise Zero Trust configuration |
| **Primary Domain** | `<PRIMARY_DOMAIN>.onmicrosoft.com` | Parameterized in `config/tenant.json` |
| **Tenant ID** | `<TENANT_ID>` | Parameterized in `config/tenant.json` |
| **Provisioning Standard** | Automated via Microsoft Graph PowerShell SDK | Scripted via `identity-lifecycle/` |
| **Architecture Model** | Enterprise Cloud-Native Zero Trust IAM | Conceptual on-premises AD DS reference architecture |

---

## 2. Security Group Matrix

All group object identifiers are dynamic and resolved at runtime via `scripts/identity/resolve_groups.ps1` from local deployment mapping:

| Group Name | Canonical Identifier | Purpose & Access Boundary | Applicable CA Policies |
|---|---|---|---|
| **`SEC-Admins`** | `<SEC_ADMINS_GROUP_ID>` | Privileged administrators holding directory roles or high-privilege operations. | CAP-001, CAP-002, CAP-003, CAP-004, CAP-005, CAP-009 |
| **`SEC-StandardUsers`** | `<SEC_STANDARDUSERS_GROUP_ID>` | Standard full-time personnel across Engineering, HR, Finance, and Marketing. | CAP-001, CAP-003, CAP-004, CAP-007 |
| **`SEC-Contractors`** | `<SEC_CONTRACTORS_GROUP_ID>` | External contractors and vendors subject to strict re-authentication timeouts. | CAP-001, CAP-003, CAP-004, CAP-005, CAP-007 |
| **`SEC-BreakGlass-Exclusion`** | `<SEC_BREAKGLASS_GROUP_ID>` | Dedicated emergency break-glass exclusion group. Membership strictly limited to 2 emergency accounts. | Excluded from CAP-001, CAP-002, CAP-003, CAP-004, CAP-005 |

---

## 3. User Population Catalogue

### 3.1 Privileged Administrative Accounts (`SEC-Admins`)
| User Principal Name (UPN) | Display Name | Assigned Role / Department | Security Controls |
|---|---|---|---|
| `adm-alex@<PRIMARY_DOMAIN>` | Alex Chen (Admin) | Security Administrator / Infosec | Phishing-resistant MFA (FIDO2), 8hr Sign-in Frequency, Non-persistent browser |
| `adm-morgan@<PRIMARY_DOMAIN>` | Morgan Vance (Admin) | Privileged Role Administrator / IAM | Phishing-resistant MFA (FIDO2), 8hr Sign-in Frequency, Non-persistent browser |

### 3.2 Standard Workforce Accounts (`SEC-StandardUsers`)
| User Principal Name (UPN) | Display Name | Department | Role |
|---|---|---|---|
| `usr-jordan@<PRIMARY_DOMAIN>` | Jordan Blake | Finance | Financial Analyst |
| `usr-taylor@<PRIMARY_DOMAIN>` | Taylor Reese | Marketing | Marketing Specialist |
| `usr-casey@<PRIMARY_DOMAIN>` | Casey Smith | Engineering | Software Engineer |
| `usr-riley@<PRIMARY_DOMAIN>` | Riley Evans | Human Resources | HR Coordinator |

### 3.3 Third-Party / Contractor Accounts (`SEC-Contractors`)
| User Principal Name (UPN) | Display Name | Organization / Scope | Enforced Controls |
|---|---|---|---|
| `cnt-sam@<PRIMARY_DOMAIN>` | Sam Rivera (Contractor) | External Audit | 8-hour session reauthentication, no persistent cookies |
| `cnt-pat@<PRIMARY_DOMAIN>` | Pat Patel (Contractor) | DevOps Consultant | 8-hour session reauthentication, no persistent cookies |

### 3.4 Dual Emergency Break-Glass Accounts (NIST & Microsoft Best Practice)
To prevent catastrophic administrative lockout during Conditional Access misconfiguration or federation outages, exactly two cloud-only break-glass accounts are maintained:

| User Principal Name (UPN) | Display Name | Storage & Auth Mechanism | Monitoring & Governance |
|---|---|---|---|
| `emergency-admin-01@<PRIMARY_DOMAIN>` | Emergency Break-Glass 01 | Hardware FIDO2 Security Key (Safe A); Complex 40+ char pass-phrase split in sealed tamper-evident envelope | Real-time SIEM alert on any sign-in attempt; 90-day drill; excluded via `SEC-BreakGlass-Exclusion` |
| `emergency-admin-02@<PRIMARY_DOMAIN>` | Emergency Break-Glass 02 | Hardware FIDO2 Security Key (Safe B - secondary physical facility); Complex 40+ char pass-phrase split in sealed tamper-evident envelope | Real-time SIEM alert on any sign-in attempt; 90-day drill; excluded via `SEC-BreakGlass-Exclusion` |

#### Operational Constraints for Emergency Accounts:
1. **Cloud-Only:** Never synchronized from on-premises AD DS (resilient to on-prem / sync server outages).
2. **Exclusion Standard:** Excluded from Conditional Access policies *only* via group assignment to `SEC-BreakGlass-Exclusion` (never hardcoded by user GUID).
3. **No Everyday Use:** Zero mailbox or productivity license assignment; strictly used for recovery.
