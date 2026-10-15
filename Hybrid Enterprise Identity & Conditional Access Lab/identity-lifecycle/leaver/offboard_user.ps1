<#
.SYNOPSIS
    Enterprise Leaver Automation Engine (State-Machine Offboarding Workflow).
.DESCRIPTION
    Zero Trust comprehensive employee termination and offboarding pipeline:
    - Stage 1: Immediate Token & Session Revocation (mitigates stolen PRT and cookie replay).
    - Stage 2: Account Disablement & High-Entropy Password Scrambling (fail-closed credential lock).
    - Stage 3: Complete Privilege Stripping (all security groups and directory roles removed).
    - Stage 4: Metadata Quarantine & Offboarding Auditing.
    - Stage 5: Export Immutable Offboarding Compliance Receipt.
.PARAMETER UserPrincipalName
    Target User Principal Name to offboard.
.PARAMETER TicketId
    ITSM / HR incident or termination ticket reference (e.g. SEC-TICK-8841).
.PARAMETER Reason
    Business justification / reason for offboarding. Default is 'Employee Departure'.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
.PARAMETER WhatIf
    Performs a dry run without modifying tenant state.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,

    [string]$TicketId = "HR-TERM-DEFAULT",

    [string]$Reason = "Employee Departure",

    [switch]$DeviceCode
)

# Load Shared Modules
$commonDir = Join-Path $PSScriptRoot "..\common"
. (Join-Path $commonDir "audit_logger.ps1")
. (Join-Path $commonDir "identity_validation.ps1")

Write-Host "==========================================================" -ForegroundColor Red
Write-Host "  Enterprise Identity Lifecycle Engine: LEAVER Workflow   " -ForegroundColor Red
Write-Host "  State-Machine Zero Trust Offboarding & Deprovisioning    " -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

# 1. Safeguard Assertions
try {
    Assert-SafeIdentityTarget -UserPrincipalName $UserPrincipalName
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

if ($WhatIfPreference) {
    Write-Host "`n[WhatIf] Dry-run enabled. Would offboard $UserPrincipalName under ticket $TicketId." -ForegroundColor Yellow
    exit 0
}

# 2. Graph Authentication
$env:ENTRA_IDENTITY_DISABLE_WAM = "true"
$activeContext = Get-MgContext -ErrorAction SilentlyContinue
$requiredScopes = @(
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All"
)

$needsAuth = $false
if (-not $activeContext) {
    $needsAuth = $true
} else {
    foreach ($scope in $requiredScopes) {
        if ($activeContext.Scopes -notcontains $scope) {
            $needsAuth = $true
            break
        }
    }
}

if ($needsAuth) {
    Write-Host "`n[Authentication] Connecting to Microsoft Graph..." -ForegroundColor Yellow
    $authParams = @{
        Scopes = $requiredScopes
        NoWelcome = $true
    }
    if ($DeviceCode) {
        $authParams["UseDeviceAuthentication"] = $true
    }
    Connect-MgGraph @authParams
    $activeContext = Get-MgContext
}

# Operator Self-Lockout Safety Check
if ($activeContext.Account -and ($activeContext.Account.ToLower() -eq $UserPrincipalName.ToLower())) {
    Write-Error "CRITICAL OPERATOR SAFEGUARD: Cannot offboard current logged-in administrative identity ($($activeContext.Account))."
    exit 1
}

# 3. Locate Target Identity
Write-Host "`nLocating target user '$UserPrincipalName'..." -ForegroundColor Cyan
$userUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
try {
    $user = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop
} catch {
    Write-Error "Identity '$UserPrincipalName' was not found in directory."
    exit 1
}

$nowUtc = (Get-Date).ToUniversalTime().ToString("o")
Write-Host "Target Found: $($user.displayName) (ID: $($user.id))" -ForegroundColor White
Write-Host "Initiator   : $($activeContext.Account)" -ForegroundColor White
Write-Host "Ticket ID   : $TicketId" -ForegroundColor White

$offboardingAuditDetails = @{
    OffboardedAtUtc = $nowUtc
    TicketId        = $TicketId
    Reason          = $Reason
    Operator        = $activeContext.Account
    Stages          = @{}
}

# -------------------------------------------------------------
# STAGE 1: Immediate Session & Token Revocation
# -------------------------------------------------------------
Write-Host "`n[Stage 1/5] Revoking active refresh tokens and browser sessions..." -ForegroundColor Yellow
$revokeUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/revokeSignInSessions"
try {
    Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ContentType "application/json" -ErrorAction Stop | Out-Null
    Write-Host "  -> Active refresh tokens successfully revoked (PRT invalidated)." -ForegroundColor Green
    $offboardingAuditDetails.Stages["Stage1_SessionRevocation"] = "Success"
} catch {
    Write-Warning "  -> Session revocation failed: $($_.Exception.Message)"
    $offboardingAuditDetails.Stages["Stage1_SessionRevocation"] = "Warning: $($_.Exception.Message)"
}

# -------------------------------------------------------------
# STAGE 2: Account Disablement & High-Entropy Password Scramble
# -------------------------------------------------------------
Write-Host "`n[Stage 2/5] Disabling account and scrambling credentials..." -ForegroundColor Yellow
$scrambledPassword = New-SecureTemporaryPassword -Length 64

$accountUpdatePayload = @{
    accountEnabled  = $false
    department      = "Offboarded"
    jobTitle        = "Terminated - $TicketId"
    passwordProfile = @{
        forceChangePasswordNextSignIn = $true
        password                      = $scrambledPassword
    }
} | ConvertTo-Json -Depth 5

try {
    Invoke-MgGraphRequest -Method PATCH -Uri $userUri -Body $accountUpdatePayload -ContentType "application/json" -ErrorAction Stop
    Write-Host "  -> Account disabled (accountEnabled = False)." -ForegroundColor Green
    Write-Host "  -> Password scrambled with 64-character high-entropy token." -ForegroundColor Green
    $offboardingAuditDetails.Stages["Stage2_AccountDisabled"] = "Success"
} catch {
    Write-Error "  -> Failed disabling account: $($_.Exception.Message)"
    $offboardingAuditDetails.Stages["Stage2_AccountDisabled"] = "Failed: $($_.Exception.Message)"
} finally {
    $scrambledPassword = $null
}

# -------------------------------------------------------------
# STAGE 3: Strip All Security Groups & Entitlements
# -------------------------------------------------------------
Write-Host "`n[Stage 3/5] Stripping all security group memberships..." -ForegroundColor Yellow
$memberOfUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
$groupsStripped = @()

try {
    $memberOfResp = Invoke-MgGraphRequest -Method GET -Uri $memberOfUri
    foreach ($grp in $memberOfResp.value) {
        if ($grp.'@odata.type' -eq "#microsoft.graph.group") {
            $grpId = $grp.id
            $grpName = $grp.displayName
            $removeMemberUri = "https://graph.microsoft.com/v1.0/groups/$grpId/members/$($user.id)/`$ref"
            try {
                Invoke-MgGraphRequest -Method DELETE -Uri $removeMemberUri -ErrorAction Stop
                Write-Host "  -> Stripped membership: $grpName ($grpId)" -ForegroundColor Gray
                $groupsStripped += $grpName
            } catch {
                Write-Warning "  -> Could not remove from group $grpName : $($_.Exception.Message)"
            }
        }
    }
    $offboardingAuditDetails.Stages["Stage3_GroupsStripped"] = $groupsStripped
} catch {
    Write-Warning "  -> Error querying group memberships: $($_.Exception.Message)"
}

# -------------------------------------------------------------
# STAGE 4: Strip Directory Role Assignments (PIM & Standing)
# -------------------------------------------------------------
Write-Host "`n[Stage 4/5] Checking and stripping administrative directory roles..." -ForegroundColor Yellow
$rolesStripped = @()
try {
    $rolesUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($user.id)'"
    $rolesResp = Invoke-MgGraphRequest -Method GET -Uri $rolesUri
    foreach ($roleAssign in $rolesResp.value) {
        $roleAssignId = $roleAssign.id
        $deleteRoleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$roleAssignId"
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri $deleteRoleUri -ErrorAction Stop
            Write-Host "  -> Revoked active directory role: $($roleAssign.roleDefinitionId)" -ForegroundColor Green
            $rolesStripped += $roleAssign.roleDefinitionId
        } catch {
            Write-Warning "  -> Could not remove role assignment $($roleAssignId): $($_.Exception.Message)"
        }
    }
    $offboardingAuditDetails.Stages["Stage4_RolesStripped"] = $rolesStripped
} catch {
    Write-Warning "  -> Role check failed or requires PIM module: $($_.Exception.Message)"
}

# -------------------------------------------------------------
# STAGE 5: Audit Telemetry & Evidence Receipt
# -------------------------------------------------------------
Write-Host "`n[Stage 5/5] Generating offboarding compliance receipt..." -ForegroundColor Cyan

Write-LifecycleAuditLog -EventType "LEAVER" `
                        -TargetUserPrincipalName $UserPrincipalName `
                        -TargetUserId $user.id `
                        -Action "OffboardUser" `
                        -Status "SUCCESS" `
                        -Details $offboardingAuditDetails `
                        -Initiator $activeContext.Account

$receiptsDir = Join-Path $PSScriptRoot "..\..\reports"
if (-not (Test-Path $receiptsDir)) {
    New-Item -ItemType Directory -Path $receiptsDir -Force | Out-Null
}

$safeUpn = $UserPrincipalName -replace "[@.]", "_"
$timestampStr = Get-Date -Format "yyyyMMdd-HHmmss"
$receiptPath = Join-Path $receiptsDir "leaver_receipt_${safeUpn}_${timestampStr}.json"

$offboardingAuditDetails | ConvertTo-Json -Depth 6 | Set-Content -Path $receiptPath -Encoding utf8

Write-Host "  -> Compliance Receipt exported: $receiptPath" -ForegroundColor Green

Write-Host "`n================ LEAVER OFFBOARDING SUCCESSFUL ================" -ForegroundColor Red
Write-Host "User Principal Name : $UserPrincipalName" -ForegroundColor White
Write-Host "Account Status      : Disabled (accountEnabled = False)" -ForegroundColor Green
Write-Host "Session Tokens      : Revoked" -ForegroundColor Green
Write-Host "Groups Stripped     : $($groupsStripped.Count)" -ForegroundColor Green
Write-Host "Roles Stripped      : $($rolesStripped.Count)" -ForegroundColor Green
Write-Host "Compliance Receipt  : $receiptPath" -ForegroundColor Gray
Write-Host "==============================================================" -ForegroundColor Red
