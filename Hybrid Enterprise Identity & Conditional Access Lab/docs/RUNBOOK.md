# Conditional Access Implementation & Staging Runbook

## 1. Overview
This runbook documents the exact procedures required to reproduce, audit, and operationalize the Entra ID Conditional Access architecture in a production-like environment.

---

## 2. Phase 1: Identity Model Provisioning

### 2.1 Prerequisites
- Windows PowerShell 5.1 or PowerShell Core 7+
- Microsoft Graph PowerShell SDK (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Groups`)
- Entra ID Global Administrator role on target tenant

### 2.2 Execution
1. Clone the repository and navigate to the project directory.
2. Execute the seeding script:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   & ".\scripts\seed_users.ps1"
   ```
3. When prompted in the browser, log in with the Global Administrator account and grant admin consent for the directory permissions (`User.ReadWrite.All`, `Group.ReadWrite.All`, `Directory.ReadWrite.All`).
4. Verify the creation of groups (`SEC-Admins`, `SEC-StandardUsers`, `SEC-Contractors`) and test user accounts in the Entra ID portal.

---

## 3. Phase 2: Conditional Access Staging Procedure

### 3.1 Golden Rule: Report-Only Staging
Every Conditional Access policy **must** be deployed in **Report-only** mode first:
- Allows telemetry collection in **Sign-in logs > Report-only** tab without impacting active user traffic.
- Validates that legitimate administrative or business workflows will not trigger false positives.
- Provides immediate auditability for SOC and IAM teams.

### 3.2 Policy Configuration Sequence
1. **Named Location Setup:**
   - Define trusted home countries / operational zones under **Named locations** prior to policy linkage.
2. **Break-Glass Exclusion:**
   - Ensure `Emergency Break-Glass Admin` is explicitly excluded from every blocking and MFA policy to guarantee emergency tenant access.
3. **Deploy Policies CAP-001 through CAP-005** with State = `Report-only`.

---

## 4. Phase 3: Validation & Evidence Testing

### 4.1 "What If" Simulation
1. Navigate to **Conditional Access > Policies > What If**.
2. Select target user (e.g., `usr-jordan@quickheal327.onmicrosoft.com`), cloud app (`All cloud apps`), client app (`Browser`), and an unapproved country (e.g., `Germany`).
3. Execute simulation and verify `CAP-001` evaluates as **Block access**.

### 4.2 Live Authentication Testing
1. In an InPrivate/Incognito window, initiate sign-in with `adm-alex@quickheal327.onmicrosoft.com`.
2. Observe immediate intervention requiring strong MFA registration (`mysignins.microsoft.com/register`).
3. Verify the sign-in attempt record in **Monitoring > Sign-in logs**, confirming policy application state.
