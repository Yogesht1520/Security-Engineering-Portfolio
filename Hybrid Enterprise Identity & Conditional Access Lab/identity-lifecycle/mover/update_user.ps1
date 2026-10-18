<#
.SYNOPSIS
    Enterprise Mover Automation Engine (Departmental / Role Transition).
.DESCRIPTION
    Automates internal identity transitions while preventing Privilege Creep:
    - Reconciles role-based security group memberships.
    - Strips former departmental and administrative group memberships.
    - Adds new required RBAC group entitlements.
    - Updates user profile attributes (Department, JobTitle).
    - Forcibly invalidates all active refresh tokens and browser sessions to prevent token reuse.
    - Records immutable audit telemetry.
.PARAMETER UserPrincipalName
    Target User Principal Name of the moving identity.
.PARAMETER NewDepartment
    Target business unit/department.
.PARAMETER NewJobTitle
    Target corporate job title.
.PARAMETER GroupNameOverride
    Optional manual override for new security group.
.PARAMETER TransactionPolicy
    Failure policy for mover transitions: 'FailClosedOnPrivilegePurge' (default, blocks new group assignment if legacy group removal fails) or 'Permissive'.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
.PARAMETER WhatIf
    Performs a dry run without modifying tenant state.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$true)]
    [string]$NewDepartment,

    [Parameter(Mandatory=$true)]
    [string]$NewJobTitle,

    [string]$GroupNameOverride,

    [string]$TargetGroupId,

    [Parameter(Mandatory=$false)]
    [ValidateSet("FailClosedOnPrivilegePurge", "Permissive")]
    [string]$TransactionPolicy = "FailClosedOnPrivilegePurge",

    [switch]$DeviceCode
)

# Load Shared Modules
$commonDir = Join-Path $PSScriptRoot "..\common"
. (Join-Path $commonDir "audit_logger.ps1")
. (Join-Path $commonDir "identity_validation.ps1")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity Lifecycle Engine: MOVER Workflow    " -ForegroundColor Cyan
Write-Host "  Privilege Creep Prevention & Session Re-evaluation     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Safeguard Verification
try {
    Assert-SafeIdentityTarget -UserPrincipalName $UserPrincipalName
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

$targetGroup = if ($GroupNameOverride) { $GroupNameOverride } else { Get-RbacGroupForDepartment -Department $NewDepartment }

Write-Host "`n[Transition Plan]:" -ForegroundColor White
Write-Host "  User Principal Name : $UserPrincipalName"
Write-Host "  New Department      : $NewDepartment"
Write-Host "  New Job Title       : $NewJobTitle"
Write-Host "  Target RBAC Group   : $targetGroup"

if ($WhatIfPreference) {
    Write-Host "`n[WhatIf] Dry-run enabled. Would transfer $UserPrincipalName to $NewDepartment / $targetGroup and flush active sessions." -ForegroundColor Yellow
    exit 0
}

# 2. Graph Authentication
$env:ENTRA_IDENTITY_DISABLE_WAM = "true"
$activeContext = Get-MgContext -ErrorAction SilentlyContinue
$requiredScopes = @("User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All")

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

# 3. Locate Target User & Current Profile
Write-Host "`n[Step 1/5] Retrieving existing user state..." -ForegroundColor Cyan
$userUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
try {
    $user = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop
} catch {
    Write-Error "Identity '$UserPrincipalName' was not found in directory: $($_.Exception.Message)"
    exit 1
}

Write-Host "  -> Identity Found: $($user.displayName) (Current Dept: $($user.department), Title: $($user.jobTitle))" -ForegroundColor Gray

# Transaction-Style Stage Tracking
$stageResults = [ordered]@{
    Stage1_TargetGroupResolution        = "Pending"
    Stage2_LegacyPrivilegePurge         = "Pending"
    Stage3_TargetGroupAssignment        = "Pending"
    Stage4_ProfileUpdate                = "Pending"
    Stage5_SessionRevocation            = "Pending"
    Stage6_FinalDirectoryReconciliation = "Pending"
}

# 4. Resolve Target Group ID (Finding 9: Support immutable ID & fail closed on duplicate display names)
Write-Host "`n[Step 2/5] Resolving target group '$targetGroup'..." -ForegroundColor Cyan
if ($TargetGroupId) {
    $targetGroupId = $TargetGroupId
    $targetGroupUri = "https://graph.microsoft.com/v1.0/groups/$TargetGroupId"
    try {
        $tgObj = Invoke-MgGraphRequest -Method GET -Uri $targetGroupUri -ErrorAction Stop
        $targetGroup = $tgObj.displayName
        Write-Host "  -> Resolved by immutable ID: $targetGroup ($targetGroupId)" -ForegroundColor Gray
        $stageResults["Stage1_TargetGroupResolution"] = "Completed"
    } catch {
        $stageResults["Stage1_TargetGroupResolution"] = "Failed: InvalidGroupId ($($_.Exception.Message))"
        Write-Error "Target group ID '$TargetGroupId' not found in tenant: $($_.Exception.Message)"
        exit 1
    }
} else {
    $targetGroupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$targetGroup'"
    try {
        $targetGroupResp = Invoke-MgGraphRequest -Method GET -Uri $targetGroupUri -ErrorAction Stop
        if (-not $targetGroupResp.value -or @($targetGroupResp.value).Count -eq 0) {
            $stageResults["Stage1_TargetGroupResolution"] = "Failed: GroupNotFound"
            Write-Error "Target security group '$targetGroup' not found in tenant."
            exit 1
        }
        if (@($targetGroupResp.value).Count -gt 1) {
            $stageResults["Stage1_TargetGroupResolution"] = "Failed: DuplicateGroupAmbiguity"
            Write-Error "[FAIL-CLOSED GATE] Multiple groups ($(@($targetGroupResp.value).Count)) match target display name '$targetGroup'. Cannot determine target group identity! Provide -TargetGroupId."
            exit 1
        }
        $targetGroupId = $targetGroupResp.value[0].id
        $stageResults["Stage1_TargetGroupResolution"] = "Completed"
    } catch {
        $stageResults["Stage1_TargetGroupResolution"] = "Failed: $($_.Exception.Message)"
        Write-Error "Error querying target group '$targetGroup': $($_.Exception.Message)"
        exit 1
    }
}

# 5. Privilege Creep Remediation: Remove Legacy RBAC Groups
Write-Host "`n[Step 3/5] Inspecting memberships to strip legacy role privileges..." -ForegroundColor Cyan
$managedRbacGroups = @("SEC-StandardUsers", "SEC-Admins", "SEC-Contractors")
$removedGroups = @()
$purgeFailed = $false
$allUserGroups = @()

try {
    $memberOfUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
    do {
        $memberOfResp = Invoke-MgGraphRequest -Method GET -Uri $memberOfUri -ErrorAction Stop
        if ($memberOfResp.value) { $allUserGroups += $memberOfResp.value }
        $memberOfUri = $memberOfResp.'@odata.nextLink'
    } while ($memberOfUri)

    foreach ($grp in $allUserGroups) {
        $grpName = $grp.displayName
        if ($grpName -in $managedRbacGroups -and $grpName -ne $targetGroup) {
            Write-Host "  [Revoking Legacy Group] Removing user from '$grpName'..." -ForegroundColor Yellow
            $removeMemberUri = "https://graph.microsoft.com/v1.0/groups/$($grp.id)/members/$($user.id)/`$ref"
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke membership in legacy group '$grpName'")) {
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri $removeMemberUri -ErrorAction Stop
                    Write-Host "  -> Stripped legacy membership: $grpName" -ForegroundColor Green
                    $removedGroups += $grpName
                } catch {
                    Write-Warning "Failed removing from group $grpName : $($_.Exception.Message)"
                    $purgeFailed = $true
                }
            }
        }
    }
    $stageResults["Stage2_LegacyPrivilegePurge"] = if ($purgeFailed) { "PartiallyCompleted" } else { "Completed" }
} catch {
    Write-Warning "Failed inspecting group memberships: $($_.Exception.Message)"
    $stageResults["Stage2_LegacyPrivilegePurge"] = "Failed: $($_.Exception.Message)"
}

# Add to New Target Group (if not already member)
if ($TransactionPolicy -eq "FailClosedOnPrivilegePurge" -and ($stageResults["Stage2_LegacyPrivilegePurge"] -ne "Completed")) {
    Write-Host "  [PRIVILEGE CREEP SAFEGUARD] Aborting target group assignment because Stage 2 (Legacy Privilege Purge) did not complete cleanly." -ForegroundColor Red
    Write-Host "  Prevents user from retaining both legacy and target permissions concurrently." -ForegroundColor Red
    $stageResults["Stage3_TargetGroupAssignment"] = "Blocked: PrivilegePurgeIncomplete"
} else {
    $isAlreadyMember = $allUserGroups | Where-Object { $_.displayName -eq $targetGroup }
    if (-not $isAlreadyMember) {
        Write-Host "  [Granting Target Group] Adding user to '$targetGroup'..." -ForegroundColor Cyan
        $addMemberUri = "https://graph.microsoft.com/v1.0/groups/$targetGroupId/members/`$ref"
        $addMemberPayload = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)"
        } | ConvertTo-Json
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Assign membership in target group '$targetGroup'")) {
            try {
                Invoke-MgGraphRequest -Method POST -Uri $addMemberUri -Body $addMemberPayload -ContentType "application/json" -ErrorAction Stop
                Write-Host "  -> Added to new group: $targetGroup" -ForegroundColor Green
                $stageResults["Stage3_TargetGroupAssignment"] = "Completed"
            } catch {
                Write-Warning "Failed adding user to target group $targetGroup : $($_.Exception.Message)"
                $stageResults["Stage3_TargetGroupAssignment"] = "Failed: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Host "  -> User already member of target group: $targetGroup" -ForegroundColor Gray
        $stageResults["Stage3_TargetGroupAssignment"] = "Completed"
    }
}

# 6. Update User Profile Attributes
Write-Host "`n[Step 4/5] Updating user directory profile..." -ForegroundColor Cyan
if ($stageResults["Stage3_TargetGroupAssignment"] -like "Blocked*") {
    Write-Host "  [Profile Update Suspended] User profile change skipped until group transition is cleanly reconciled." -ForegroundColor Yellow
    $stageResults["Stage4_ProfileUpdate"] = "Blocked: PrerequisiteFailed"
} else {
    $updatePayload = @{
        department = $NewDepartment
        jobTitle   = $NewJobTitle
    } | ConvertTo-Json

    try {
        Invoke-MgGraphRequest -Method PATCH -Uri $userUri -Body $updatePayload -ContentType "application/json" -ErrorAction Stop
        Write-Host "  -> Profile updated: Department='$NewDepartment', JobTitle='$NewJobTitle'" -ForegroundColor Green
        $stageResults["Stage4_ProfileUpdate"] = "Completed"
    } catch {
        Write-Warning "Failed updating profile attributes: $($_.Exception.Message)"
        $stageResults["Stage4_ProfileUpdate"] = "Failed: $($_.Exception.Message)"
    }
}

# 7. Invalidate Active Sessions (Mitigate Stolen PRT & Stale Group Token Claims)
Write-Host "`n[Step 5/5] Flushing active refresh tokens and sign-in sessions..." -ForegroundColor Cyan
$revokeUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/revokeSignInSessions"
try {
    Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ContentType "application/json" -ErrorAction Stop | Out-Null
    Write-Host "  -> Active refresh tokens successfully revoked. Next sign-in will evaluate new Conditional Access claims." -ForegroundColor Green
    $stageResults["Stage5_SessionRevocation"] = "Completed"
} catch {
    Write-Warning "  -> Could not revoke sessions: $($_.Exception.Message)"
    $stageResults["Stage5_SessionRevocation"] = "Failed: $($_.Exception.Message)"
}

# 7.5. Independent Final State Directory Reconciliation Gate (Item 9)
Write-Host "`n[Step 5.5] Independently reconciling final directory state against desired target..." -ForegroundColor Cyan
try {
    # Query live memberships independently
    $reconciledMemberships = @()
    $reconUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
    do {
        $reconResp = Invoke-MgGraphRequest -Method GET -Uri $reconUri -ErrorAction Stop
        if ($reconResp.value) { $reconciledMemberships += $reconResp.value }
        $reconUri = $reconResp.'@odata.nextLink'
    } while ($reconUri)

    $reconciledGroupNames = @($reconciledMemberships | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" } | ForEach-Object { $_.displayName })
    $targetPresent = $reconciledGroupNames -contains $targetGroup
    $lingeringLegacy = @($legacyRbacGroups | Where-Object { $reconciledGroupNames -contains $_.displayName })

    if (-not $targetPresent) {
        $stageResults["Stage3_TargetGroupAssignment"] = "Failed: Target group '$targetGroup' missing in post-reconciliation directory query"
    }
    if ($lingeringLegacy.Count -gt 0) {
        $lingeringNames = ($lingeringLegacy | ForEach-Object { $_.displayName }) -join ", "
        $stageResults["Stage2_LegacyPrivilegePurge"] = "PartiallyCompleted: Lingering legacy memberships detected ($lingeringNames)"
    }

    # Re-query user profile to assert department and jobTitle
    $reconUser = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop
    $profileMatch = ($reconUser.department -eq $NewDepartment -and $reconUser.jobTitle -eq $NewJobTitle)
    if (-not $profileMatch) {
        $stageResults["Stage4_ProfileUpdate"] = "Failed: Attribute parity failure (Dept: $($reconUser.department), Title: $($reconUser.jobTitle))"
    }

    Write-Host "  -> Directory State Reconciliation: TargetPresent=$targetPresent, LingeringLegacyCount=$($lingeringLegacy.Count), ProfileMatch=$profileMatch" -ForegroundColor Green
    $stageResults["Stage6_FinalDirectoryReconciliation"] = if ($targetPresent -and $lingeringLegacy.Count -eq 0 -and $profileMatch) { "Completed" } else { "Incomplete: ParityMismatch" }
} catch {
    Write-Warning "  -> [WARNING] Independent final reconciliation query failed: $($_.Exception.Message)"
    $stageResults["Stage6_FinalDirectoryReconciliation"] = "Incomplete: $($_.Exception.Message)"
}

# 8. Evaluate Overall Transaction State
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

# Record Audit Telemetry
Write-LifecycleAuditLog -EventType "MOVER" `
                        -TargetUserPrincipalName $UserPrincipalName `
                        -TargetUserId $user.id `
                        -Action "TransitionUser" `
                        -Status $overallState `
                        -Details @{
                            OverallState   = $overallState
                            StageBreakdown = $stageResults
                            OldDepartment  = $user.department
                            NewDepartment  = $NewDepartment
                            OldJobTitle    = $user.jobTitle
                            NewJobTitle    = $NewJobTitle
                            RemovedGroups  = ($removedGroups -join ", ")
                            NewGroup       = $targetGroup
                        } `
                        -Initiator $activeContext.Account

$statusColor = switch ($overallState) {
    "Completed"          { "Green" }
    "PartiallyCompleted" { "Yellow" }
    "Failed"             { "Red" }
    Default              { "Cyan" }
}

Write-Host "`n================ MOVER TRANSITION TRANSACTION: $overallState ================" -ForegroundColor $statusColor
Write-Host "User Principal Name : $UserPrincipalName" -ForegroundColor Cyan
Write-Host "Transaction Status  : $overallState" -ForegroundColor $statusColor
Write-Host "Department          : $NewDepartment ($($stageResults['Stage4_ProfileUpdate']))" -ForegroundColor White
Write-Host "Job Title           : $NewJobTitle" -ForegroundColor White
Write-Host "Assigned RBAC Group : $targetGroup ($($stageResults['Stage3_TargetGroupAssignment']))" -ForegroundColor White
Write-Host "Legacy Groups Purged: $(if($removedGroups.Count -gt 0){$removedGroups -join ', '}else{'None'}) ($($stageResults['Stage2_LegacyPrivilegePurge']))" -ForegroundColor White
Write-Host "Session State       : $($stageResults['Stage5_SessionRevocation'])" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor $statusColor
