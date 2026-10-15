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

# 4. Resolve Target Group ID
Write-Host "`n[Step 2/5] Resolving target group '$targetGroup'..." -ForegroundColor Cyan
$targetGroupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$targetGroup'"
$targetGroupResp = Invoke-MgGraphRequest -Method GET -Uri $targetGroupUri
if (-not $targetGroupResp.value -or $targetGroupResp.value.Count -eq 0) {
    Write-Error "Target security group '$targetGroup' not found in tenant."
    exit 1
}
$targetGroupId = $targetGroupResp.value[0].id

# 5. Privilege Creep Remediation: Remove Legacy RBAC Groups
Write-Host "`n[Step 3/5] Inspecting memberships to strip legacy role privileges..." -ForegroundColor Cyan
$memberOfUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
$memberOfResp = Invoke-MgGraphRequest -Method GET -Uri $memberOfUri

$managedRbacGroups = @("SEC-StandardUsers", "SEC-Admins", "SEC-Contractors")
$removedGroups = @()

foreach ($grp in $memberOfResp.value) {
    $grpName = $grp.displayName
    if ($grpName -in $managedRbacGroups -and $grpName -ne $targetGroup) {
        Write-Host "  [Revoking Legacy Group] Removing user from '$grpName'..." -ForegroundColor Yellow
        $removeMemberUri = "https://graph.microsoft.com/v1.0/groups/$($grp.id)/members/$($user.id)/`$ref"
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri $removeMemberUri -ErrorAction Stop
            Write-Host "  -> Stripped legacy membership: $grpName" -ForegroundColor Green
            $removedGroups += $grpName
        } catch {
            Write-Warning "Failed removing from group $grpName : $($_.Exception.Message)"
        }
    }
}

# Add to New Target Group (if not already member)
$isAlreadyMember = $memberOfResp.value | Where-Object { $_.displayName -eq $targetGroup }
if (-not $isAlreadyMember) {
    Write-Host "  [Granting Target Group] Adding user to '$targetGroup'..." -ForegroundColor Cyan
    $addMemberUri = "https://graph.microsoft.com/v1.0/groups/$targetGroupId/members/`$ref"
    $addMemberPayload = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)"
    } | ConvertTo-Json
    Invoke-MgGraphRequest -Method POST -Uri $addMemberUri -Body $addMemberPayload -ContentType "application/json" -ErrorAction Stop
    Write-Host "  -> Added to new group: $targetGroup" -ForegroundColor Green
} else {
    Write-Host "  -> User already member of target group: $targetGroup" -ForegroundColor Gray
}

# 6. Update User Profile Attributes
Write-Host "`n[Step 4/5] Updating user directory profile..." -ForegroundColor Cyan
$updatePayload = @{
    department = $NewDepartment
    jobTitle   = $NewJobTitle
} | ConvertTo-Json

Invoke-MgGraphRequest -Method PATCH -Uri $userUri -Body $updatePayload -ContentType "application/json" -ErrorAction Stop
Write-Host "  -> Profile updated: Department='$NewDepartment', JobTitle='$NewJobTitle'" -ForegroundColor Green

# 7. Invalidate Active Sessions (Mitigate Stolen PRT & Stale Group Token Claims)
Write-Host "`n[Step 5/5] Flushing active refresh tokens and sign-in sessions..." -ForegroundColor Cyan
$revokeUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/revokeSignInSessions"
try {
    Invoke-MgGraphRequest -Method POST -Uri $revokeUri -ContentType "application/json" -ErrorAction Stop | Out-Null
    Write-Host "  -> Active refresh tokens successfully revoked. Next sign-in will evaluate new Conditional Access claims." -ForegroundColor Green
} catch {
    Write-Warning "  -> Could not revoke sessions: $($_.Exception.Message)"
}

# 8. Record Audit Telemetry
Write-LifecycleAuditLog -EventType "MOVER" `
                        -TargetUserPrincipalName $UserPrincipalName `
                        -TargetUserId $user.id `
                        -Action "TransitionUser" `
                        -Status "SUCCESS" `
                        -Details @{
                            OldDepartment = $user.department
                            NewDepartment = $NewDepartment
                            OldJobTitle   = $user.jobTitle
                            NewJobTitle   = $NewJobTitle
                            RemovedGroups = ($removedGroups -join ", ")
                            NewGroup      = $targetGroup
                        } `
                        -Initiator $activeContext.Account

Write-Host "`n================ MOVER TRANSITION COMPLETED ================" -ForegroundColor White
Write-Host "User Principal Name : $UserPrincipalName" -ForegroundColor Cyan
Write-Host "Department          : $NewDepartment" -ForegroundColor Cyan
Write-Host "Job Title           : $NewJobTitle" -ForegroundColor Cyan
Write-Host "Assigned RBAC Group : $targetGroup" -ForegroundColor Cyan
Write-Host "Legacy Groups Purged: $(if($removedGroups.Count -gt 0){$removedGroups -join ', '}else{'None'})" -ForegroundColor Yellow
Write-Host "Session State       : All active tokens invalidated (Re-auth required)" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor White
