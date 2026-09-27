# Enterprise Identity & Access Management Model

## 1. Directory Overview

| Property | Value |
|---|---|
| **Identity Platform** | Microsoft Entra ID (P2 Active) |
| **Primary Domain** | `quickheal327.onmicrosoft.com` |
| **Tenant ID** | `464a788a-fba5-4e94-9b06-a6359091ad74` |
| **Provisioning Standard** | Automated via Microsoft Graph PowerShell SDK (`seed_users.ps1`) |
| **Architecture Model** | Cloud-native simulation of Hybrid Zero Trust IAM |

---

## 2. Security Group Matrix

| Group Name | Object ID | Purpose & Access Boundary | Applicable CA Policies |
|---|---|---|---|
| **`SEC-Admins`** | `10a34fab-c98d-4a85-84e9-42b92e96fe82` | Privileged administrators holding directory roles or high-privilege operations. | CAP-001, CAP-002, CAP-003, CAP-004, CAP-005 |
| **`SEC-StandardUsers`** | `bb2d5dcc-cdd9-413f-85a8-f256171aa177` | Standard full-time personnel across Engineering, HR, Finance, and Marketing. | CAP-001, CAP-003, CAP-004 |
| **`SEC-Contractors`** | `369c861a-5277-459f-abc4-7cc86d61b2e1` | External contractors and vendors subject to strict re-authentication timeouts. | CAP-001, CAP-003, CAP-004, CAP-005 |

---

## 3. User Population Catalogue

### 3.1 Privileged Administrative Accounts (`SEC-Admins`)
| User Principal Name (UPN) | Display Name | Assigned Role / Department | Security Controls |
|---|---|---|---|
| `adm-alex@quickheal327.onmicrosoft.com` | Alex Chen (Admin) | Security Administrator / Infosec | Mandatory MFA, 8hr Sign-in Frequency, Non-persistent browser |
| `adm-morgan@quickheal327.onmicrosoft.com` | Morgan Vance (Admin) | IAM Administrator / Identity & Access | Mandatory MFA, 8hr Sign-in Frequency, Non-persistent browser |

### 3.2 Standard Workforce Accounts (`SEC-StandardUsers`)
| User Principal Name (UPN) | Display Name | Department | Role |
|---|---|---|---|
| `usr-jordan@quickheal327.onmicrosoft.com` | Jordan Blake | Finance | Financial Analyst |
| `usr-taylor@quickheal327.onmicrosoft.com` | Taylor Reese | Marketing | Marketing Specialist |
| `usr-casey@quickheal327.onmicrosoft.com` | Casey Smith | Engineering | Software Engineer |
| `usr-riley@quickheal327.onmicrosoft.com` | Riley Evans | Human Resources | HR Coordinator |

### 3.3 Third-Party / Contractor Accounts (`SEC-Contractors`)
| User Principal Name (UPN) | Display Name | Organization / Scope | Enforced Controls |
|---|---|---|---|
| `cnt-sam@quickheal327.onmicrosoft.com` | Sam Rivera (Contractor) | External Audit | 8-hour session lifetime, no persistent cookies |
| `cnt-pat@quickheal327.onmicrosoft.com` | Pat Patel (Contractor) | DevOps Consultant | 8-hour session lifetime, no persistent cookies |

### 3.4 Emergency Break-Glass Account (Exempt Account)
| User Principal Name (UPN) | Display Name | Purpose | Exemption Scope |
|---|---|---|---|
| `emergency-admin@quickheal327.onmicrosoft.com` | Emergency Break-Glass Admin | Emergency tenant recovery in catastrophic CA misconfiguration | Excluded from CAP-001, CAP-002, CAP-003, CAP-004, CAP-005 |
