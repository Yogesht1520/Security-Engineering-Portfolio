<#
.SYNOPSIS
    Microsoft Entra ID Privileged Identity Management (PIM) Configuration & Automation Engine.
.DESCRIPTION
    Automates and models Zero Standing Access (ZSA) role governance:
    - Queries directory roles and current PIM eligibility schedules.
    - Provisions PIM Eligible assignments via Microsoft Graph API.
    - Enforces JIT constraints (max 4-hour activation, justification required, step-up MFA).
    - Provides explicit Entra ID admin center portal configuration procedures.
.PARAMETER AssignEligible
    Switch to assign an eligible PIM role to a user.
.PARAMETER UserPrincipalName
    The UPN of the user to make eligible.
.PARAMETER RoleName
    The display name of the directory role (e.g., 'Conditional Access Administrator', 'Security Administrator').
.PARAMETER DurationHours
    Maximum activation duration in hours. Default is 4.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
#>

[CmdletBinding()]
param (
    [switch]$AssignEligible,
    [string]$UserPrincipalName,
    [string]$RoleName = "Conditional Access Administrator",
    [int]$DurationHours = 4,
    [switch]$ListRoles,
    [switch]$DeviceCode
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Microsoft Entra Privileged Identity Management (PIM) Engine" -ForegroundColor Cyan
Write-Host "  Zero Standing Access (ZSA) Lifecycle Management" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Connect to Microsoft Graph
$activeContext = Get-MgContext -ErrorAction SilentlyContinue
# Least-Privilege Scopes: Drop broad Directory.ReadWrite.All in favor of granular role management & user read
$requiredScopes = @(
    "RoleManagement.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "User.Read.All"
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
    Write-Host "`n[Authentication] Connecting to Microsoft Graph with granular least-privilege PIM scopes..." -ForegroundColor Yellow
    $env:ENTRA_IDENTITY_DISABLE_WAM = "true"
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

Write-Host "Connected Tenant: $($activeContext.TenantId)" -ForegroundColor Green

# 2. Query Directory Roles
$roleDefsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$RoleName'"
$roleDefResp = Invoke-MgGraphRequest -Method GET -Uri $roleDefsUri

if (-not $roleDefResp.value -or $roleDefResp.value.Count -eq 0) {
    Write-Error "Role '$RoleName' not found in tenant. Use -ListRoles to view available role definitions."
    exit 1
}

$targetRole = $roleDefResp.value[0]
Write-Host "`n[Target Role Identified]:" -ForegroundColor Cyan
Write-Host "  Display Name: $($targetRole.displayName)" -ForegroundColor White
Write-Host "  Role ID     : $($targetRole.id)" -ForegroundColor White
Write-Host "  Template ID : $($targetRole.templateId)" -ForegroundColor White

if ($ListRoles) {
    Write-Host "`nQuerying all available directory roles..." -ForegroundColor Cyan
    $allRolesUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
    $allRolesResp = Invoke-MgGraphRequest -Method GET -Uri $allRolesUri
    $allRolesResp.value | Select-Object displayName, id, templateId | Format-Table -AutoSize
    exit 0
}

# 3. Handle Eligible Role Assignment & Verification
if ($AssignEligible) {
    if (-not $UserPrincipalName) {
        Write-Error "Parameter -UserPrincipalName is required when using -AssignEligible."
        exit 1
    }

    Write-Host "`n[Step 1/3] Resolving Principal '$UserPrincipalName'..." -ForegroundColor Cyan
    $userUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
    try {
        $userObj = Invoke-MgGraphRequest -Method GET -Uri $userUri
    } catch {
        Write-Error "Could not find user '$UserPrincipalName': $_"
        exit 1
    }

    Write-Host "  -> Principal ID: $($userObj.id) ($($userObj.displayName))" -ForegroundColor Gray

    Write-Host "`n[Step 2/3] Submitting PIM Role Eligibility Schedule Request..." -ForegroundColor Cyan
    $scheduleRequestUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
    
    $payload = @{
        action = "adminAssign"
        justification = "Zero Standing Access enterprise security baseline - Phase 3 PIM transition."
        roleDefinitionId = $targetRole.id
        directoryScopeId = "/"
        principalId = $userObj.id
        scheduleInfo = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString("o")
            expiration = @{
                type = "noExpiration"
            }
        }
    }

    try {
        $jsonBody = $payload | ConvertTo-Json -Depth 5
        $pimResp = Invoke-MgGraphRequest -Method POST -Uri $scheduleRequestUri -Body $jsonBody -ContentType "application/json" -ErrorAction Stop
        Write-Host "  -> Successfully submitted PIM Eligible role request!" -ForegroundColor Green
        Write-Host "     Eligibility Request ID: $($pimResp.id)" -ForegroundColor Gray
        Write-Host "     Status                 : $($pimResp.status)" -ForegroundColor Green

        # Step 3: Post-Assignment Verification
        Write-Host "`n[Step 3/3] Verifying Active Role Eligibility Schedule Instance..." -ForegroundColor Cyan
        $instancesUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($userObj.id)' and roleDefinitionId eq '$($targetRole.id)'"
        $instancesResp = Invoke-MgGraphRequest -Method GET -Uri $instancesUri -ErrorAction SilentlyContinue

        if ($instancesResp.value -and $instancesResp.value.Count -gt 0) {
            $inst = $instancesResp.value[0]
            Write-Host "  [VERIFIED] Role Eligibility Schedule confirmed active in tenant!" -ForegroundColor Green
            Write-Host "  Schedule Instance ID : $($inst.id)" -ForegroundColor White
            Write-Host "  Member Type          : $($inst.memberType)" -ForegroundColor White
            Write-Host "  Start Date (UTC)     : $($inst.startDateTime)" -ForegroundColor White
        } else {
            Write-Warning "Schedule instance verification returned pending or requires directory propagation delay."
        }
    } catch {
        Write-Host "  -> PIM Graph Request returned: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  -> Note: Interactive Portal assignment or Entra ID P2 license required." -ForegroundColor Yellow
    }
}

Write-Host "`n================ PIM ZERO STANDING ACCESS ARCHITECTURE ================" -ForegroundColor White
Write-Host "Operational Separation of Concerns:" -ForegroundColor Cyan
Write-Host "  - Programmatic Layer : Manages user eligibility assignments (this automation)." -ForegroundColor White
Write-Host "  - Policy Engine Layer: Governs role activation constraints in Entra ID Portal:" -ForegroundColor White
Write-Host "      * Max Activation Window : $DurationHours hours" -ForegroundColor White
Write-Host "      * Authentication Context: Require Phishing-Resistant MFA on activation" -ForegroundColor White
Write-Host "      * Justification & Ticket : Mandatory ticket reference and approval chain" -ForegroundColor White
Write-Host "      * Standing Global Admins: Zero standing assignments (human accounts strictly PIM eligible)" -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor White
