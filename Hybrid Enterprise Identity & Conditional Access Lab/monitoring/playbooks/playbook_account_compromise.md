# Incident Response Playbook: Identity Compromise & Token Hijack

## Severity: HIGH to CRITICAL
**Target Scenarios:**
- Stolen Primary Refresh Token (PRT) or browser cookie session replay.
- Phished credentials or MFA fatigue concession.
- High User Risk flag triggered in Microsoft Entra ID Identity Protection.

---

## 1. Triage & Scoping (Phase 1: Identification)

1. **Verify Sign-in Anomalies:**
   - Query `SigninLogs` for the affected User Principal Name (UPN) over the last 24 hours:
     ```kql
     SigninLogs
     | where UserPrincipalName =~ "compromised.user@domain.com"
     | project TimeGenerated, IPAddress, Location, AppDisplayName, ClientAppUsed, RiskLevelDuringSignIn, ConditionalAccessStatus
     | order by TimeGenerated desc
     ```
2. **Inspect Identity Protection State:**
   - In Entra admin center: Navigate to **Protection** > **Identity Protection** > **Risky users**.
   - Note the detected risk events: *Anonymous IP address*, *Atypical travel*, *Malicious IP*, or *Leaked credentials*.

---

## 2. Containment & Neutralization (Phase 2: Immediate Containment)

Execute the 4-stage containment sequence:

### Step 1: Kill All Active Sessions & Tokens (T=0)
Prevent the attacker from using stolen OAuth access tokens or PRTs:
```powershell
# Using Graph PowerShell or JML Leaver module
Revoke-MgUserSignInSession -UserId "<User-Object-ID>"
```

### Step 2: Immediate Password Reset (Scramble)
Scramble the password to prevent password-spray or continued access:
```powershell
$tempPassword = New-SecureTemporaryPassword -Length 32
Update-MgUser -UserId "<User-Object-ID>" -PasswordProfile @{
    forceChangePasswordNextSignIn = $true
    password                      = $tempPassword
}
```

### Step 3: Revoke Registered MFA Authentication Methods
If an attacker registered an unauthorized FIDO2 key, phone number, or Authenticator app:
```powershell
# List registered auth methods
Get-MgUserAuthenticationMethod -UserId "<User-Object-ID>"
# Remove unauthorized methods
```

### Step 4: Dismiss User Risk & Re-evaluate
Once containment is verified, in **Protection** > **Identity Protection** > **Risky users**, click **Confirm user compromised** during investigation, and **Dismiss user risk** only after full remediation.

---

## 3. Post-Incident Eradication & Recovery

1. Audit Mailbox Forwarding and Inbox Rules:
   - Check if the attacker created inbox forwarding rules (`New-InboxRule`, `ForwardTo`) to exfiltrate emails.
2. Audit OAuth App Consents:
   - Check if malicious Enterprise Apps were granted OAuth permissions by the user.
3. Validate Conditional Access:
   - Confirm user is scoped under **CAP-003** (Risk-Based Step-Up MFA) and **CAP-012** (High User Risk Remediation).
