<#
.SYNOPSIS
    Enterprise Leaver Automation Engine (State-Machine Offboarding Workflow).
.DESCRIPTION
    Zero Trust employee termination and offboarding pipeline:
    - Stage 1: Immediate Token & Session Revocation (mitigates stolen PRT and cookie replay).
      Note: Revoking sessions issues a Graph revocation request; active access tokens may remain valid
      until standard expiry (up to 60-90 min) unless Continuous Access Evaluation (CAE) applies.
    - Stage 2: Account Disablement & High-Entropy Password Scrambling (fail-closed credential lock).
    - Stage 3: Complete Privilege Stripping (all security groups purged with post-removal verification).
    - Stage 4: Administrative Role Revocation (standing active roles and eligible PIM schedules).
    - Stage 5: Export Immutable Offboarding Compliance Receipt & Audit Telemetry.

    COVERAGE BOUNDARIES & SCOPE LIMITATIONS:
    This workflow automates core Entra ID directory deprovisioning. The following boundaries
    require separate resource-specific deprovisioning controls:
    - Azure RBAC assignments (Azure subscriptions / management groups / resource groups)
    - Application role assignments & Enterprise application assignments
    - Group and application ownership
    - M365 license assignment & mailbox archiving
    - Exchange Online, SharePoint site, and Teams-specific permissions
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
}

# Transaction-Style Stage Tracking
$stageResults = [ordered]@{
    Stage1_SessionRevocation = "Pending"
    Stage2_AccountDisabled   = "Pending"
    Stage3_GroupsStripped    = "Pending"
    Stage4_RolesStripped     = "Pending"
}

# -------------------------------------------------------------
# STAGE 1: Immediate Session & Token Revocation
# -------------------------------------------------------------
Write-Host "`n[Stage 1/5] Requesting revocation of active refresh tokens and browser sessions..." -ForegroundColor Yellow
$revokeUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/revokeSignInSessions"
try {
    Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ContentType "application/json" -ErrorAction Stop | Out-Null
    Write-Host "  -> Refresh token revocation requested (PRT invalidated)." -ForegroundColor Green
    Write-Host "     [Boundary Note] Access tokens remain valid until expiration (~60-90m) unless Continuous Access Evaluation (CAE) applies." -ForegroundColor Gray
    $stageResults["Stage1_SessionRevocation"] = "Completed: RevocationRequested"
} catch {
    Write-Warning "  -> Session revocation failed: $($_.Exception.Message)"
    $stageResults["Stage1_SessionRevocation"] = "Failed: $($_.Exception.Message)"
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
    $stageResults["Stage2_AccountDisabled"] = "Completed"
} catch {
    Write-Error "  -> Failed disabling account: $($_.Exception.Message)"
    $stageResults["Stage2_AccountDisabled"] = "Failed: $($_.Exception.Message)"
} finally {
    $scrambledPassword = $null
}

# -------------------------------------------------------------
# STAGE 3: Strip All Security Groups & Entitlements (with Pagination & Verification)
# -------------------------------------------------------------
Write-Host "`n[Stage 3/5] Stripping all security group memberships..." -ForegroundColor Yellow
$allGroups = @()
$stripFailed = $false
$groupsStripped = @()

try {
    $memberOfUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
    do {
        $memberOfResp = Invoke-MgGraphRequest -Method GET -Uri $memberOfUri -ErrorAction Stop
        if ($memberOfResp.value) { $allGroups += $memberOfResp.value }
        $memberOfUri = $memberOfResp.'@odata.nextLink'
    } while ($memberOfUri)

    foreach ($grp in $allGroups) {
        if ($grp.'@odata.type' -eq "#microsoft.graph.group") {
            $grpId = $grp.id
            $grpName = $grp.displayName
            $removeMemberUri = "https://graph.microsoft.com/v1.0/groups/$grpId/members/$($user.id)/`$ref"
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove membership from security group '$grpName' ($grpId)")) {
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri $removeMemberUri -ErrorAction Stop
                    Write-Host "  -> Stripped membership: $grpName ($grpId)" -ForegroundColor Gray
                    $groupsStripped += $grpName
                } catch {
                    Write-Warning "  -> Could not remove from group $grpName : $($_.Exception.Message)"
                    $stripFailed = $true
                }
            }
        }
    }
    
    # Finding 9: Independent post-removal group membership verification
    Write-Host "  Verifying group memberships are completely purged from directory..." -ForegroundColor Gray
    $remainingGroups = [System.Collections.Generic.List[string]]::new()
    $verifyMemberUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
    do {
        $vResp = Invoke-MgGraphRequest -Method GET -Uri $verifyMemberUri -ErrorAction Stop
        if ($vResp.value) {
            foreach ($vg in $vResp.value) {
                if ($vg.'@odata.type' -eq "#microsoft.graph.group") {
                    $remainingGroups.Add($vg.displayName)
                }
            }
        }
        $verifyMemberUri = $vResp.'@odata.nextLink'
    } while ($verifyMemberUri)

    if ($remainingGroups.Count -gt 0 -or $stripFailed) {
        $lingeringStr = $remainingGroups -join ", "
        $stageResults["Stage3_GroupsStripped"] = "PartiallyCompleted: RemainingGroups=($lingeringStr)"
        Write-Warning "  -> [WARNING] Group purge incomplete! Remaining memberships: $lingeringStr"
    } else {
        $stageResults["Stage3_GroupsStripped"] = "Completed"
        Write-Host "  -> [VERIFIED] All security group memberships confirmed purged." -ForegroundColor Green
    }
} catch {
    Write-Warning "  -> Error querying group memberships: $($_.Exception.Message)"
    $stageResults["Stage3_GroupsStripped"] = "Failed: $($_.Exception.Message)"
}

# -------------------------------------------------------------
# STAGE 4: Strip Directory Role Assignments (Standing Active & PIM Eligible - Item 11)
# -------------------------------------------------------------
Write-Host "`n[Stage 4/5] Checking and stripping administrative directory roles (Active & PIM Eligible)..." -ForegroundColor Yellow
$rolesStripped = @()
$failedRoleRemovals = [System.Collections.Generic.List[string]]::new()

try {
    # 4.1. Strip Active Standing Directory Roles
    $rolesUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($user.id)'"
    do {
        $rolesResp = Invoke-MgGraphRequest -Method GET -Uri $rolesUri -ErrorAction Stop
        if ($rolesResp.value) {
            foreach ($roleAssign in $rolesResp.value) {
                $roleAssignId = $roleAssign.id
                $deleteRoleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$roleAssignId"
                if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke active directory role assignment $($roleAssign.roleDefinitionId)")) {
                    try {
                        Invoke-MgGraphRequest -Method DELETE -Uri $deleteRoleUri -ErrorAction Stop
                        Write-Host "  -> Revoked active directory role: $($roleAssign.roleDefinitionId)" -ForegroundColor Green
                        $rolesStripped += "Active-$($roleAssign.roleDefinitionId)"
                    } catch {
                        Write-Warning "  -> Could not remove active role assignment $($roleAssignId): $($_.Exception.Message)"
                        $failedRoleRemovals.Add("Active-$($roleAssignId): $($_.Exception.Message)")
                    }
                }
            }
        }
        $rolesUri = $rolesResp.'@odata.nextLink'
    } while ($rolesUri)

    # 4.2. Revoke Eligible PIM Role Assignments (Item 11: Fail-closed query and individual tracking)
    Write-Host "  Auditing PIM eligible role schedules..." -ForegroundColor Gray
    $pimSchedUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($user.id)'"
    do {
        $pimSchedResp = Invoke-MgGraphRequest -Method GET -Uri $pimSchedUri -ErrorAction Stop
        if ($pimSchedResp.value) {
            foreach ($sched in $pimSchedResp.value) {
                $roleDefId = $sched.roleDefinitionId
                if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke PIM eligible role schedule $roleDefId")) {
                    Write-Host "  -> Revoking PIM eligible role schedule: $roleDefId (Schedule ID: $($sched.id))..." -ForegroundColor Yellow
                    $removePimPayload = @{
                        action           = "adminRemove"
                        justification    = "Automated Leaver Offboarding - Ticket: $TicketId"
                        roleDefinitionId = $roleDefId
                        directoryScopeId = "/"
                        principalId      = $user.id
                    } | ConvertTo-Json
                    try {
                        $reqUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
                        Invoke-MgGraphRequest -Method POST -Uri $reqUri -Body $removePimPayload -ContentType "application/json" -ErrorAction Stop | Out-Null
                        Write-Host "  -> Successfully revoked PIM eligible role: $roleDefId" -ForegroundColor Green
                        $rolesStripped += "PIM-Eligible-$roleDefId"
                    } catch {
                        Write-Warning "  -> Failed removing PIM eligible schedule $($sched.id): $($_.Exception.Message)"
                        $failedRoleRemovals.Add("PIM-Eligible-$($roleDefId): $($_.Exception.Message)")
                    }
                }
            }
        }
        $pimSchedUri = $pimSchedResp.'@odata.nextLink'
    } while ($pimSchedUri)

    # 4.3. Independent Post-Removal Verification Gate (Item 11)
    Write-Host "  Verifying active and eligible role assignments are completely purged..." -ForegroundColor Gray
    $remainingActive = @()
    $checkActiveUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($user.id)'"
    $checkActiveResp = Invoke-MgGraphRequest -Method GET -Uri $checkActiveUri -ErrorAction Stop
    if ($checkActiveResp.value) { $remainingActive = @($checkActiveResp.value) }

    $remainingEligible = @()
    $checkEligibleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($user.id)'"
    $checkEligibleResp = Invoke-MgGraphRequest -Method GET -Uri $checkEligibleUri -ErrorAction Stop
    if ($checkEligibleResp.value) { $remainingEligible = @($checkEligibleResp.value) }

    if ($remainingActive.Count -gt 0 -or $remainingEligible.Count -gt 0 -or $failedRoleRemovals.Count -gt 0) {
        $stageResults["Stage4_RolesStripped"] = "PartiallyCompleted: RemainingActive=$($remainingActive.Count), RemainingEligible=$($remainingEligible.Count), Failures=$($failedRoleRemovals.Count)"
        Write-Warning "  -> [WARNING] Role purge incomplete! Active remaining: $($remainingActive.Count), Eligible remaining: $($remainingEligible.Count)"
    } else {
        $stageResults["Stage4_RolesStripped"] = "Completed"
        Write-Host "  -> [VERIFIED] All administrative directory roles confirmed purged from tenant." -ForegroundColor Green
    }
} catch {
    Write-Warning "  -> Role query failed: $($_.Exception.Message)"
    $stageResults["Stage4_RolesStripped"] = "Failed: $($_.Exception.Message)"
}

# -------------------------------------------------------------
# STAGE 5: Transaction Evaluation, Audit Telemetry & Evidence Receipt
# -------------------------------------------------------------
Write-Host "`n[Stage 5/5] Evaluating transaction state and generating offboarding compliance receipt..." -ForegroundColor Cyan

$totalStages = $stageResults.Count
$failedStages = ($stageResults.Values | Where-Object { $_ -like "Failed*" }).Count
$partialStages = ($stageResults.Values | Where-Object { $_ -eq "PartiallyCompleted" }).Count
$completedStages = ($stageResults.Values | Where-Object { $_ -eq "Completed" }).Count

$overallState = if ($failedStages -eq 0 -and $partialStages -eq 0 -and $completedStages -eq $totalStages) {
    "Completed"
} elseif ($completedStages -gt 0 -or $partialStages -gt 0) {
    "PartiallyCompleted"
} elseif ($failedStages -eq $totalStages) {
    "Failed"
} else {
    "PendingVerification"
}

$offboardingAuditDetails["OverallState"]   = $overallState
$offboardingAuditDetails["StageBreakdown"] = $stageResults
$offboardingAuditDetails["GroupsStripped"] = $groupsStripped
$offboardingAuditDetails["RolesStripped"]  = $rolesStripped

$auditLogged = $true
try {
    Write-LifecycleAuditLog -EventType "LEAVER" `
                            -TargetUserPrincipalName $UserPrincipalName `
                            -TargetUserId $user.id `
                            -Action "OffboardUser" `
                            -Status $overallState `
                            -Details $offboardingAuditDetails `
                            -Initiator $activeContext.Account
} catch {
    $auditLogged = $false
    Write-Error "[AUDIT LOGGING FAILURE] Offboarding actions executed, but writing the audit log record failed: $($_.Exception.Message)"
}

$receiptsDir = Join-Path $PSScriptRoot "..\..\reports"
if (-not (Test-Path $receiptsDir)) {
    New-Item -ItemType Directory -Path $receiptsDir -Force | Out-Null
}

$safeUpn = $UserPrincipalName -replace "[@.]", "_"
$timestampStr = Get-Date -Format "yyyyMMdd-HHmmss"
$receiptPath = Join-Path $receiptsDir "leaver_receipt_${safeUpn}_${timestampStr}.json"
$receiptSaved = $true

try {
    $offboardingAuditDetails | ConvertTo-Json -Depth 6 | Set-Content -Path $receiptPath -Encoding utf8
    Write-Host "  -> Compliance Receipt exported: $receiptPath" -ForegroundColor Green
} catch {
    $receiptSaved = $false
    Write-Error "[RECEIPT EXPORT FAILURE] Writing the compliance receipt file failed: $($_.Exception.Message)"
}

if (-not $auditLogged -or -not $receiptSaved) {
    $overallState = "PartiallyCompleted: AuditRecordOrReceiptFailed"
    Write-Warning "  -> [TRANSACTION WARNING] Transaction marked PartiallyCompleted due to audit/receipt failure."
}

$statusColor = switch ($overallState) {
    "Completed"          { "Green" }
    "PartiallyCompleted" { "Yellow" }
    "Failed"             { "Red" }
    Default              { "Cyan" }
}

Write-Host "`n================ LEAVER OFFBOARDING TRANSACTION: $overallState ================" -ForegroundColor $statusColor
Write-Host "User Principal Name : $UserPrincipalName" -ForegroundColor White
Write-Host "Transaction Status  : $overallState" -ForegroundColor $statusColor
Write-Host "Account Status      : $($stageResults['Stage2_AccountDisabled'])" -ForegroundColor White
Write-Host "Session Tokens      : $($stageResults['Stage1_SessionRevocation'])" -ForegroundColor White
Write-Host "Groups Stripped     : $($groupsStripped.Count) ($($stageResults['Stage3_GroupsStripped']))" -ForegroundColor White
Write-Host "Roles Stripped      : $($rolesStripped.Count) ($($stageResults['Stage4_RolesStripped']))" -ForegroundColor White
Write-Host "Compliance Receipt  : $receiptPath" -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor $statusColor
