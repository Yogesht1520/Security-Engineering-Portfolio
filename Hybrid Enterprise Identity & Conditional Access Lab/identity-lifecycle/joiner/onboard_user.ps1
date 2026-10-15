<#
.SYNOPSIS
    Enterprise Joiner Automation Engine (Onboarding Workflow).
.DESCRIPTION
    Automates secure employee and contractor onboarding in Microsoft Entra ID:
    - Generates high-entropy cryptographically secure temporary passwords.
    - Enforces mandatory password change on first sign-in.
    - Dynamically evaluates Role-Based Access Control (RBAC) security group mapping.
    - Configures usage location, job title, and department metadata.
    - Writes structured, compliance-ready audit telemetry.
.PARAMETER GivenName
    User's first name.
.PARAMETER Surname
    User's last name.
.PARAMETER UserPrincipalName
    Target User Principal Name (e.g. usr-jane@domain.onmicrosoft.com).
.PARAMETER Department
    Business unit/department (e.g. Finance, Marketing, Information Security, External Contractors).
.PARAMETER JobTitle
    Corporate job title.
.PARAMETER UsageLocation
    ISO 2-letter country code for Microsoft 365 licensing eligibility. Default is 'US'.
.PARAMETER GroupNameOverride
    Optional manual override for assigned security group.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
.PARAMETER WhatIf
    Performs a dry run without modifying tenant state.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [string]$GivenName,

    [Parameter(Mandatory=$true)]
    [string]$Surname,

    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$true)]
    [string]$Department,

    [Parameter(Mandatory=$true)]
    [string]$JobTitle,

    [string]$UsageLocation = "US",

    [string]$GroupNameOverride,

    [switch]$DeviceCode
)

# Load Shared Modules
$commonDir = Join-Path $PSScriptRoot "..\common"
. (Join-Path $commonDir "audit_logger.ps1")
. (Join-Path $commonDir "identity_validation.ps1")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity Lifecycle Engine: JOINER Workflow   " -ForegroundColor Cyan
Write-Host "  Zero Trust Automated Identity Provisioning              " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Pre-Flight Validation & Safeguards
try {
    Assert-SafeIdentityTarget -UserPrincipalName $UserPrincipalName
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

$displayName = "$GivenName $Surname"
$mailNickname = $UserPrincipalName.Split("@")[0]
$assignedGroup = if ($GroupNameOverride) { $GroupNameOverride } else { Get-RbacGroupForDepartment -Department $Department }

Write-Host "`n[Candidate Metadata]:" -ForegroundColor White
Write-Host "  Name              : $displayName"
Write-Host "  UPN               : $UserPrincipalName"
Write-Host "  Department        : $Department"
Write-Host "  Job Title         : $JobTitle"
Write-Host "  Target RBAC Group : $assignedGroup"

if ($WhatIfPreference) {
    Write-Host "`n[WhatIf] Dry-run enabled. Would provision $UserPrincipalName and assign to $assignedGroup." -ForegroundColor Yellow
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

# 3. Check for Duplicate UPN
Write-Host "`n[Step 1/3] Checking for duplicate user in directory..." -ForegroundColor Cyan
$checkUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
try {
    $existing = Invoke-MgGraphRequest -Method GET -Uri $checkUri -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Error "Identity with UPN '$UserPrincipalName' already exists in tenant (ID: $($existing.id))."
        Write-LifecycleAuditLog -EventType "JOINER" -TargetUserPrincipalName $UserPrincipalName -Action "ProvisionUser" -Status "FAILURE" -Details @{ Error = "UserAlreadyExists" } -Initiator $activeContext.Account
        exit 1
    }
} catch {
    # 404 is expected for new accounts
    Write-Verbose "User not found (expected for new onboarding identity): $($_.Exception.Message)"
}

# 4. Resolve Target Group
Write-Host "`n[Step 2/3] Resolving target RBAC group '$assignedGroup'..." -ForegroundColor Cyan
$groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$assignedGroup'"
$groupResp = Invoke-MgGraphRequest -Method GET -Uri $groupUri
if (-not $groupResp.value -or $groupResp.value.Count -eq 0) {
    Write-Error "Target security group '$assignedGroup' was not found in directory. Ensure Phase 0 seeds were executed."
    exit 1
}
$targetGroupId = $groupResp.value[0].id
Write-Host "  -> Group Verified: $assignedGroup (ID: $targetGroupId)" -ForegroundColor Gray

# 5. Provision User with High-Entropy Password
Write-Host "`n[Step 3/3] Provisioning user account in Entra ID..." -ForegroundColor Cyan
$tempPassword = New-SecureTemporaryPassword -Length 24

$newUserPayload = @{
    accountEnabled    = $true
    displayName       = $displayName
    givenName         = $GivenName
    surname           = $Surname
    userPrincipalName = $UserPrincipalName
    mailNickname      = $mailNickname
    department        = $Department
    jobTitle          = $JobTitle
    usageLocation     = $UsageLocation
    passwordProfile   = @{
        forceChangePasswordNextSignIn = $true
        password                      = $tempPassword
    }
}

try {
    $createUri = "https://graph.microsoft.com/v1.0/users"
    $jsonPayload = $newUserPayload | ConvertTo-Json -Depth 5
    $createdUser = Invoke-MgGraphRequest -Method POST -Uri $createUri -Body $jsonPayload -ContentType "application/json" -ErrorAction Stop

    Write-Host "  -> Successfully created user object (ID: $($createdUser.id))" -ForegroundColor Green

    # Assign to Security Group
    $addGroupMemberUri = "https://graph.microsoft.com/v1.0/groups/$targetGroupId/members/`$ref"
    $memberPayload = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($createdUser.id)"
    } | ConvertTo-Json

    Invoke-MgGraphRequest -Method POST -Uri $addGroupMemberUri -Body $memberPayload -ContentType "application/json" -ErrorAction Stop
    Write-Host "  -> Assigned membership to group: $assignedGroup" -ForegroundColor Green

    # Record Audit Telemetry
    Write-LifecycleAuditLog -EventType "JOINER" `
                            -TargetUserPrincipalName $UserPrincipalName `
                            -TargetUserId $createdUser.id `
                            -Action "OnboardUser" `
                            -Status "SUCCESS" `
                            -Details @{
                                Department   = $Department
                                JobTitle     = $JobTitle
                                AssignedGroup = $assignedGroup
                            } `
                            -Initiator $activeContext.Account

    # Display Provisioning Credential Packet
    Write-Host "`n================ ONBOARDING CREDENTIAL PACKET ================" -ForegroundColor White
    Write-Host "User Principal Name : $UserPrincipalName" -ForegroundColor Cyan
    Write-Host "Display Name        : $displayName" -ForegroundColor Cyan
    Write-Host "Assigned RBAC Group : $assignedGroup" -ForegroundColor Cyan
    Write-Host "Temporary Password  : $tempPassword" -ForegroundColor Yellow
    Write-Host "Password Policy     : Mandatory change required on first sign-in" -ForegroundColor Gray
    Write-Host "Conditional Access  : Enforced under baseline workforce MFA (CAP-007)" -ForegroundColor Gray
    Write-Host "==============================================================" -ForegroundColor White

} catch {
    Write-Error "Failed to provision user: $($_.Exception.Message)"
    Write-LifecycleAuditLog -EventType "JOINER" `
                            -TargetUserPrincipalName $UserPrincipalName `
                            -Action "OnboardUser" `
                            -Status "FAILURE" `
                            -Details @{ Error = $_.Exception.Message } `
                            -Initiator $activeContext.Account
    exit 1
} finally {
    # Secure memory cleanup
    $tempPassword = $null
    $newUserPayload.passwordProfile.password = $null
}
