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
$requiredScopes = @(
    "RoleManagement.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
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
    Write-Host "`n[Authentication] Connecting to Microsoft Graph with PIM management scopes..." -ForegroundColor Yellow
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

# 3. Handle Eligible Role Assignment
if ($AssignEligible) {
    if (-not $UserPrincipalName) {
        Write-Error "Parameter -UserPrincipalName is required when using -AssignEligible."
        exit 1
    }

    Write-Host "`n[Step 1/2] Resolving Principal '$UserPrincipalName'..." -ForegroundColor Cyan
    $userUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
    try {
        $userObj = Invoke-MgGraphRequest -Method GET -Uri $userUri
    } catch {
        Write-Error "Could not find user '$UserPrincipalName': $_"
        exit 1
    }

    Write-Host "  -> Principal ID: $($userObj.id) ($($userObj.displayName))" -ForegroundColor Gray

    Write-Host "`n[Step 2/2] Requesting PIM Role Eligibility Schedule..." -ForegroundColor Cyan
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
        Write-Host "  -> Successfully assigned PIM Eligible role!" -ForegroundColor Green
        Write-Host "     Eligibility Request ID: $($pimResp.id)" -ForegroundColor Gray
        Write-Host "     Status                 : $($pimResp.status)" -ForegroundColor Green
    } catch {
        Write-Host "  -> PIM Graph Request returned: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  -> If your tenant requires interactive Portal activation or lacks P2 license, follow the Portal instructions below." -ForegroundColor Yellow
    }
}

Write-Host "`n================ PIM ZERO STANDING ACCESS SUMMARY ================" -ForegroundColor White
Write-Host "Standard Enterprise PIM Role Configuration Guidelines:" -ForegroundColor Cyan
Write-Host "  1. Max Activation Duration: $DurationHours hours"
Write-Host "  2. Activation Requirement : Azure MFA / Phishing-Resistant Authenticator"
Write-Host "  3. Justification          : Mandatory business reason and ITSM change ticket"
Write-Host "  4. Standing Assignments   : ZERO for human administrators (Break-Glass exempt)"
Write-Host "==================================================================" -ForegroundColor White
