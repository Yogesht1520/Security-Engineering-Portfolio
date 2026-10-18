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

    [string[]]$ManagedRbacGroupIds = @(),

    [string]$MappingConfigFile = "",

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
if (-not $TargetGroupId) {
    # Check mapping config if available
    $mappingPath = if ($MappingConfigFile) { $MappingConfigFile } else { Join-Path $PSScriptRoot "..\..\config\identity-mapping.json" }
    if (Test-Path $mappingPath) {
        try {
            $mapContent = Get-Content -Path $mappingPath -Raw | ConvertFrom-Json
            if ($mapContent.groups -and $mapContent.groups.PSObject.Properties[$targetGroup]) {
                $mappedId = $mapContent.groups.PSObject.Properties[$targetGroup].Value
                if ($mappedId -and $mappedId -notmatch "^<.*>$") {
                    $TargetGroupId = $mappedId.Trim()
                }
            }
        } catch {
            Write-Warning "Could not read target group mapping from '$mappingPath': $($_.Exception.Message)"
        }
    }
}

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
Write-Host "`n[Step 3/5] Resolving and validating complete managed RBAC group immutable IDs..." -ForegroundColor Cyan

$requiredManagedRoles = @("SEC-StandardUsers", "SEC-Admins", "SEC-Contractors")
$resolvedRoleMap = [ordered]@{}

# A. Direct parameter input of immutable IDs (if caller provided specific mapping)
if ($ManagedRbacGroupIds -and $ManagedRbacGroupIds.Count -ge $requiredManagedRoles.Count) {
    for ($i = 0; $i -lt $requiredManagedRoles.Count; $i++) {
        $gid = $ManagedRbacGroupIds[$i]
        if (-not [string]::IsNullOrWhiteSpace($gid)) {
            $resolvedRoleMap[$requiredManagedRoles[$i]] = $gid.Trim()
        }
    }
}

# B. Configuration file input of immutable IDs (evaluated per individual role)
$mappingPath = if ($MappingConfigFile) { $MappingConfigFile } else { Join-Path $PSScriptRoot "..\..\config\identity-mapping.json" }
$mapContent = $null
if (Test-Path $mappingPath) {
    try {
        $mapContent = Get-Content -Path $mappingPath -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "Could not read mapping config at '$mappingPath': $($_.Exception.Message)"
    }
}

# C. Resolve each individual required managed role (from config mapping first, then Graph with fail-closed checks)
foreach ($roleName in $requiredManagedRoles) {
    if ($resolvedRoleMap.ContainsKey($roleName)) {
        continue
    }

    # Check mapping config for this specific role
    if ($mapContent -and $mapContent.groups -and $mapContent.groups.PSObject.Properties[$roleName]) {
        $confVal = $mapContent.groups.PSObject.Properties[$roleName].Value
        if ($confVal -and $confVal -notmatch "^<.*>$") {
            $resolvedRoleMap[$roleName] = $confVal.Trim()
            continue
        }
    }

    # Fallback to Graph resolution for this role with strict fail-closed validation
    $mUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$roleName'"
    try {
        $mResp = Invoke-MgGraphRequest -Method GET -Uri $mUri -ErrorAction Stop
        $matched = @($mResp.value)
        if ($matched.Count -eq 1) {
            $resolvedRoleMap[$roleName] = $matched[0].id
        } elseif ($matched.Count -gt 1) {
            $stageResults["Stage2_LegacyPrivilegePurge"] = "Failed: DuplicateGroupAmbiguity ($roleName)"
            Write-Error "[FAIL-CLOSED GATE] Multiple groups ($($matched.Count)) match managed role name '$roleName'. Cannot resolve unambiguous immutable ID! Supply -ManagedRbacGroupIds."
            exit 1
        } else {
            $stageResults["Stage2_LegacyPrivilegePurge"] = "Failed: ManagedRoleNotFound ($roleName)"
            Write-Error "[FAIL-CLOSED GATE] Required managed RBAC group '$roleName' was not found in tenant. Aborting mover transition to prevent incomplete privilege reconciliation."
            exit 1
        }
    } catch {
        $stageResults["Stage2_LegacyPrivilegePurge"] = "Failed: GraphQueryError ($roleName - $($_.Exception.Message))"
        Write-Error "[FAIL-CLOSED GATE] Failed querying Graph for required managed group '$roleName': $($_.Exception.Message). Aborting mover transition."
        exit 1
    }
}

# D. Strict assertion: All required managed roles MUST be resolved
$missingRoles = @($requiredManagedRoles | Where-Object { -not $resolvedRoleMap.ContainsKey($_) })
if ($missingRoles.Count -gt 0) {
    $missingList = $missingRoles -join ", "
    $stageResults["Stage2_LegacyPrivilegePurge"] = "Failed: IncompleteManagedRoleResolution ($missingList)"
    Write-Error "[FAIL-CLOSED GATE] Incomplete managed RBAC group set. Could not resolve required role(s): $missingList. Halting transition before tenant state modification."
    exit 1
}

$resolvedManagedGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($roleId in $resolvedRoleMap.Values) {
    [void]$resolvedManagedGroupIds.Add($roleId)
}

Write-Host "  -> Tracking $($resolvedManagedGroupIds.Count) managed RBAC group immutable IDs for privilege creep remediation." -ForegroundColor Gray
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

    # Identify legacy managed RBAC groups strictly by immutable group ID (excluding target group ID)
    $legacyRbacGroups = @($allUserGroups | Where-Object {
        $_.id -ne $targetGroupId -and $resolvedManagedGroupIds.Contains($_.id)
    })

        foreach ($grp in $legacyRbacGroups) {
            $grpName = $grp.displayName
            Write-Host "  [Revoking Legacy Group] Removing user from '$grpName' (ID: $($grp.id))..." -ForegroundColor Yellow
            $removeMemberUri = "https://graph.microsoft.com/v1.0/groups/$($grp.id)/members/$($user.id)/`$ref"
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke membership in legacy group '$grpName'")) {
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri $removeMemberUri -ErrorAction Stop
                    Write-Host "  -> Stripped legacy membership: $grpName ($($grp.id))" -ForegroundColor Green
                    $removedGroups += $grpName
                } catch {
                    Write-Warning "Failed removing from group $grpName : $($_.Exception.Message)"
                    $purgeFailed = $true
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
        $isAlreadyMember = $allUserGroups | Where-Object { $_.id -eq $targetGroupId }
        if (-not $isAlreadyMember) {
            Write-Host "  [Granting Target Group] Adding user to '$targetGroup' ($targetGroupId)..." -ForegroundColor Cyan
            $addMemberUri = "https://graph.microsoft.com/v1.0/groups/$targetGroupId/members/`$ref"
            $addMemberPayload = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)"
            } | ConvertTo-Json
            if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Assign membership in target group '$targetGroup'")) {
                try {
                    Invoke-MgGraphRequest -Method POST -Uri $addMemberUri -Body $addMemberPayload -ContentType "application/json" -ErrorAction Stop
                    Write-Host "  -> Added to new group: $targetGroup ($targetGroupId)" -ForegroundColor Green
                    $stageResults["Stage3_TargetGroupAssignment"] = "Completed"
                } catch {
                    Write-Warning "Failed adding user to target group $targetGroup : $($_.Exception.Message)"
                    $stageResults["Stage3_TargetGroupAssignment"] = "Failed: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "  -> User already member of target group: $targetGroup ($targetGroupId)" -ForegroundColor Gray
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

    $reconciledGroupIds = @($reconciledMemberships | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" } | ForEach-Object { $_.id })
    $targetPresent = $reconciledGroupIds -contains $targetGroupId
    $lingeringLegacy = @($legacyRbacGroups | Where-Object { $reconciledGroupIds -contains $_.id })

    if (-not $targetPresent) {
        $stageResults["Stage3_TargetGroupAssignment"] = "Failed: Target group ID '$targetGroupId' ($targetGroup) missing in post-reconciliation directory query"
    }
    if ($lingeringLegacy.Count -gt 0) {
        $lingeringNames = ($lingeringLegacy | ForEach-Object { "$($_.displayName) ($($_.id))" }) -join ", "
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
$partialStages = ($stageResults.Values | Where-Object { $_ -like "PartiallyCompleted*" -or $_ -like "Incomplete*" -or $_ -like "Blocked*" }).Count
$completedStages = ($stageResults.Values | Where-Object { $_ -eq "Completed" }).Count

$overallState = if ($failedStages -eq 0 -and $partialStages -eq 0 -and $completedStages -eq $totalStages) {
    "Completed"
} elseif ($failedStages -gt 0) {
    "Failed"
} elseif ($partialStages -gt 0) {
    "PartiallyCompleted"
} else {
    "PendingVerification"
}

# Record Audit Telemetry
$auditLogged = $true
try {
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
                                TargetGroupId  = $targetGroupId
                            } `
                            -Initiator $activeContext.Account
} catch {
    $auditLogged = $false
    Write-Error "[AUDIT LOGGING FAILURE] Mover transition executed, but writing the audit log record failed: $($_.Exception.Message)"
}

# Audit persistence is a mandatory gate for completed state
if (-not $auditLogged) {
    $overallState = "Failed: AuditPersistenceFailed"
    Write-Error "  -> [TRANSACTION GATE FAILURE] Transaction marked Failed because audit log record could not be persisted."
}

$statusColor = switch -Wildcard ($overallState) {
    "Completed"          { "Green" }
    "PartiallyCompleted" { "Yellow" }
    "Failed*"            { "Red" }
    Default              { "Cyan" }
}

Write-Host "`n================ MOVER TRANSITION TRANSACTION: $overallState ================" -ForegroundColor $statusColor
Write-Host "User Principal Name : $UserPrincipalName" -ForegroundColor Cyan
Write-Host "Transaction Status  : $overallState" -ForegroundColor $statusColor
Write-Host "Department          : $NewDepartment ($($stageResults['Stage4_ProfileUpdate']))" -ForegroundColor White
Write-Host "Job Title           : $NewJobTitle" -ForegroundColor White
Write-Host "Assigned RBAC Group : $targetGroup (ID: $targetGroupId) ($($stageResults['Stage3_TargetGroupAssignment']))" -ForegroundColor White
Write-Host "Legacy Groups Purged: $(if($removedGroups.Count -gt 0){$removedGroups -join ', '}else{'None'}) ($($stageResults['Stage2_LegacyPrivilegePurge']))" -ForegroundColor White
Write-Host "Session State       : $($stageResults['Stage5_SessionRevocation'])" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor $statusColor

if ($overallState -ne "Completed") {
    Write-Error "[MOVER INCOMPLETE] Transition failed or incomplete. Final state: $overallState"
    exit 1
}
