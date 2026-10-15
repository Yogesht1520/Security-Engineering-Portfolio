# Enterprise Conditional Access & Identity Operations Runbook

## 1. Overview

This runbook documents the operational procedures required to reproduce, deploy, audit, and troubleshoot the Microsoft Entra ID Zero Trust architecture.

---

## 2. Prerequisites & Environment Setup

1. **PowerShell Environment:**
   * Windows PowerShell 5.1 or PowerShell Core 7+.
   * Microsoft Graph PowerShell SDK (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Groups`).
2. **Directory Permissions:**
   * Microsoft Entra ID Global Administrator role or Privileged Role Administrator on the target tenant.
3. **Configuration Setup:**
   * Copy `config/tenant.example.json` to `config/tenant.json` and populate your target sandbox domain and tenant GUID.
   * *(Note: `config/tenant.json` is ignored by `.gitignore` to prevent secret leakage).*

---

## 3. Directory Seeding & Break-Glass Initialization

Execute the idempotent directory seeding script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\seed_users.ps1 -Domain "<YOUR_TENANT>.onmicrosoft.com"
```

**Actions Executed:**
1. Provisions 4 security groups: `SEC-Admins`, `SEC-StandardUsers`, `SEC-Contractors`, and `SEC-BreakGlass-Exclusion`.
2. Provisions 8 synthetic workforce identities with temporary passwords (requiring password change on first logon).
3. Provisions two independent cloud-only break-glass accounts: `emergency-admin-01` and `emergency-admin-02` assigned to `SEC-BreakGlass-Exclusion`.

---

## 4. Declarative Identity-as-Code Deployment Pipeline

All 11 Conditional Access policies are maintained as declarative JSON definitions in [`policies/`](../policies/) and orchestrated via [`scripts/deploy_ca_policies.ps1`](../scripts/deploy_ca_policies.ps1).

### 4.1 Golden Rule: Safe Staging (Report-Only Mode)
Every policy definition defaults to `enabledForReportingButNotEnforced` (Report-only):
* Collects live telemetry in **Sign-in logs > Report-only** tab without impacting active user traffic.
* Validates that legitimate business workflows will not trigger false positives.
* Eliminates the risk of administrative lockout during baseline deployment.

### 4.2 Pipeline Execution Sequence

```powershell
# Step 1: Pre-flight local schema validation (No Graph network calls required)
.\scripts\deploy_ca_policies.ps1 -ValidateOnly

# Step 2: Plan / WhatIf mode (Connects to Graph, resolves dynamic GUIDs, displays drift)
.\scripts\deploy_ca_policies.ps1 -Plan -DeviceCode

# Step 3: Progressive deployment (Creates pre-deployment rollback snapshot, updates live tenant)
.\scripts\deploy_ca_policies.ps1 -Deploy -DeviceCode

# Step 4: Targeted deployment for single policy update (e.g. CAP-002)
.\scripts\deploy_ca_policies.ps1 -Deploy -DeviceCode -PolicyId "CAP-002"
```

---

## 5. Automated Rollback & Disaster Recovery

The deployment engine creates an immutable JSON snapshot before modifying any live tenant policies.

### To List Available Snapshots:
```powershell
.\scripts\deployment\rollback_policies.ps1 -Action List
```

### To Revert Live Tenant to a Prior State:
```powershell
.\scripts\deployment\rollback_policies.ps1 -Action Rollback -SnapshotId "<SNAPSHOT_TIMESTAMP>" -DeviceCode
```

---

## 6. Operational Troubleshooting & Field-Tested Remediations

During live tenant orchestration, multiple real-world operational challenges were diagnosed and resolved:

### 6.1 Headless / Embedded Terminal Authentication Hang (WAM Broker)
* **Symptom:** Running `Connect-MgGraph` interactively in headless developer terminals or embedded IDE shells hangs indefinitely or throws:
  `InteractiveBrowserCredential authentication failed: A window handle must be configured`.
* **Root Cause:** Windows Web Account Manager (WAM) requires an interactive Win32 desktop window handle, which does not exist in non-standard or embedded terminal sessions.
* **Remediation:**
  1. Add `$env:ENTRA_IDENTITY_DISABLE_WAM = "true"` prior to calling `Connect-MgGraph`.
  2. Use the `-DeviceCode` parameter to authenticate via the standard OAuth 2.0 Device Code flow (`https://microsoft.com/devicelogin`).

### 6.2 Microsoft Graph 400 Bad Request (Role Template ID Resolution)
* **Symptom:** Graph API returns `HTTP 400 Bad Request: 1103: 'users' condition contains non-built in role ids`.
* **Root Cause:** Conditional Access role targeting requires built-in Entra ID **Directory Role Template IDs**, not tenant-specific instance GUIDs or arbitrary strings.
* **Remediation:**
  Verify that role GUIDs match Microsoft's official directory role template definitions:
  * Global Administrator: `62e90394-69f5-4237-9190-012177145e10`
  * Privileged Role Administrator: `e8611ab8-c189-46e8-94e1-60213ab1f814`
  * Security Administrator: `194ae4cb-b126-40b2-bd5b-6091b380977d`
  * Conditional Access Administrator: `b1be1c3e-b65d-4f19-8427-f6fa0d97feb9`
  * User Administrator: `fe930be7-5e62-47db-91af-98c3a49a38b1`

### 6.3 Named Location Query Scopes
* **Symptom:** Graph API returns `403 Forbidden` when querying `/identity/conditionalAccess/namedLocations`.
* **Root Cause:** Reading named locations requires `Policy.Read.All` in addition to `Policy.ReadWrite.ConditionalAccess`.
* **Remediation:** Ensure both scopes are included during `Connect-MgGraph`.

### 6.4 Accidental Break-Glass Offboarding Safeguard
* **Symptom:** An automated lifecycle process or operator attempts to terminate an emergency break-glass account.
* **Remediation:** The JML engine enforces `Assert-SafeIdentityTarget`, which immediately aborts execution with a terminating error if the target starts with `emergency-admin`, preventing disaster recovery lockouts.
