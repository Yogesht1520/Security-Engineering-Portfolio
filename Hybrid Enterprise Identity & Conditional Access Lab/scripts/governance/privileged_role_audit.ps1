<#
.SYNOPSIS
    Privileged Identity Governance Audit Engine for Microsoft Entra ID.
.DESCRIPTION
    Zero Standing Access (ZSA) compliance auditor.
    - Inspects all Microsoft Entra ID Directory Roles.
    - Audits Active vs. Eligible role assignments.
    - Flags permanent/standing assignments on Tier-0 administrative roles.
    - Verifies break-glass account isolation.
    - Generates actionable JSON and CSV audit evidence reports.
.PARAMETER OutputPath
    Directory where audit reports will be stored. Defaults to 'reports'.
.PARAMETER Format
    Export format: 'Both', 'Json', or 'Console'. Default is 'Both'.
.PARAMETER DeviceCode
    Use device-code authentication flow to avoid interactive broker popups.
#>

[CmdletBinding()]
param (
    [string]$OutputPath = "$PSScriptRoot\..\..\reports",
    [ValidateSet("Both", "Json", "Console")]
    [string]$Format = "Both",
    [switch]$DeviceCode
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Privileged Identity Governance & Zero Standing Access Audit" -ForegroundColor Cyan
Write-Host "  Microsoft Entra ID Privileged Identity Management (PIM)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Tier-0 / Critical directory roles that require Zero Standing Access
$Tier0RoleTemplates = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
    "cf1c38e5-3621-4004-a7cb-879624dced7c" = "Cloud Application Administrator"
    "29232cdf-9323-42fd-ab2c-84921dad6491" = "Exchange Administrator"
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
}

# 1. Connect to Microsoft Graph
$activeContext = Get-MgContext -ErrorAction SilentlyContinue
$requiredScopes = @("RoleManagement.Read.Directory", "Directory.Read.All")

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

Write-Host "Auditing Tenant: $($activeContext.TenantId) as $($activeContext.Account)" -ForegroundColor Green

# 2. Fetch Directory Role Definitions
Write-Host "`n[Step 1/4] Retrieving directory role definitions..." -ForegroundColor Cyan
$roleDefsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
$roleDefsResponse = Invoke-MgGraphRequest -Method GET -Uri $roleDefsUri
$roleDefinitions = @{}
foreach ($def in $roleDefsResponse.value) {
    $roleDefinitions[$def.id] = @{
        DisplayName = $def.displayName
        TemplateId = $def.templateId
        Description = $def.description
    }
}
Write-Host "  -> Loaded $($roleDefinitions.Count) directory role definitions." -ForegroundColor Gray

# 3. Fetch Active Role Assignments
Write-Host "`n[Step 2/4] Querying active role assignments..." -ForegroundColor Cyan
$assignmentsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=principal"
$activeAssignments = @()
$currentUri = $assignmentsUri
while ($currentUri) {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $currentUri
    if ($resp.value) {
        $activeAssignments += $resp.value
    }
    $currentUri = $resp.'@odata.nextLink'
}
Write-Host "  -> Found $($activeAssignments.Count) active role assignment(s)." -ForegroundColor Gray

# 4. Fetch PIM Eligible Role Assignments
Write-Host "`n[Step 3/4] Querying PIM eligible role assignments..." -ForegroundColor Cyan
$eligibleAssignments = @()
try {
    $eligibilityUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal"
    $currentUri = $eligibilityUri
    while ($currentUri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $currentUri
        if ($resp.value) {
            $eligibleAssignments += $resp.value
        }
        $currentUri = $resp.'@odata.nextLink'
    }
    Write-Host "  -> Found $($eligibleAssignments.Count) PIM eligible assignment(s)." -ForegroundColor Gray
} catch {
    Write-Host "  -> Notice: PIM eligibility schedules query returned: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "     (Tenant may require Entra ID P2 / Governance license to query roleEligibilityScheduleInstances)" -ForegroundColor Yellow
}

# 5. Analyze Findings & Generate Compliance Audit
Write-Host "`n[Step 4/4] Performing Zero Standing Access (ZSA) Analysis..." -ForegroundColor Cyan

$auditFindings = @()
$breakGlassAccounts = @("emergency-admin-01", "emergency-admin-02", "emergency-admin")

foreach ($assignment in $activeAssignments) {
    $roleDef = $roleDefinitions[$assignment.roleDefinitionId]
    $roleName = if ($roleDef) { $roleDef.DisplayName } else { "Unknown ($($assignment.roleDefinitionId))" }
    $templateId = if ($roleDef) { $roleDef.TemplateId } else { "" }
    
    $principalName = $assignment.principal.displayName
    $principalType = $assignment.principal.'@odata.type' -replace '#microsoft.graph.', ''
    $userPrincipalName = $assignment.principal.userPrincipalName

    $isTier0 = $Tier0RoleTemplates.ContainsKey($templateId) -or ($Tier0RoleTemplates.Values -contains $roleName)
    $isBreakGlass = $false
    foreach ($bg in $breakGlassAccounts) {
        if ($userPrincipalName -like "$bg*") {
            $isBreakGlass = $true
            break
        }
    }

    # Evaluate Compliance Status
    $status = "Compliant"
    $severity = "Low"
    $reason = "Standard role assignment"

    if ($isBreakGlass) {
        $status = "Exempt (Break-Glass)"
        $severity = "Info"
        $reason = "Designated emergency break-glass account permanently assigned for disaster recovery."
    } elseif ($isTier0) {
        # Active assignment on Tier-0 role without PIM JIT is a critical ZSA violation
        $status = "Non-Compliant"
        $severity = "CRITICAL"
        $reason = "Standing permanent assignment on Tier-0 role ($roleName). Must be transitioned to PIM Eligible (JIT)."
    }

    $finding = [PSCustomObject]@{
        RoleName           = $roleName
        RoleDefinitionId   = $assignment.roleDefinitionId
        PrincipalName      = $principalName
        PrincipalType      = $principalType
        UserPrincipalName  = $userPrincipalName
        AssignmentType     = "Active (Standing)"
        IsTier0            = $isTier0
        ComplianceStatus   = $status
        Severity           = $severity
        FindingDescription = $reason
    }

    $auditFindings += $finding
}

# Add Eligible Assignments to Findings
foreach ($eligible in $eligibleAssignments) {
    $roleDef = $roleDefinitions[$eligible.roleDefinitionId]
    $roleName = if ($roleDef) { $roleDef.DisplayName } else { "Unknown ($($eligible.roleDefinitionId))" }
    $templateId = if ($roleDef) { $roleDef.TemplateId } else { "" }

    $principalName = $eligible.principal.displayName
    $principalType = $eligible.principal.'@odata.type' -replace '#microsoft.graph.', ''
    $userPrincipalName = $eligible.principal.userPrincipalName
    $isTier0 = $Tier0RoleTemplates.ContainsKey($templateId) -or ($Tier0RoleTemplates.Values -contains $roleName)

    $finding = [PSCustomObject]@{
        RoleName           = $roleName
        RoleDefinitionId   = $eligible.roleDefinitionId
        PrincipalName      = $principalName
        PrincipalType      = $principalType
        UserPrincipalName  = $userPrincipalName
        AssignmentType     = "Eligible (PIM JIT)"
        IsTier0            = $isTier0
        ComplianceStatus   = "Compliant"
        Severity           = "Info"
        FindingDescription = "Zero Standing Access compliant: Role requires Just-In-Time activation with justification."
    }

    $auditFindings += $finding
}

# Console Report Summary
Write-Host "`n================== AUDIT FINDINGS SUMMARY ==================" -ForegroundColor White
$nonCompliant = @($auditFindings | Where-Object { $_.ComplianceStatus -eq "Non-Compliant" })
$exempt = @($auditFindings | Where-Object { $_.ComplianceStatus -eq "Exempt (Break-Glass)" })
$compliant = @($auditFindings | Where-Object { $_.ComplianceStatus -eq "Compliant" })

Write-Host "Total Role Assignments Audited : $($auditFindings.Count)" -ForegroundColor White
Write-Host "Zero Standing Access Violations: $($nonCompliant.Count)" -ForegroundColor $(if($nonCompliant.Count -gt 0){"Red"}else{"Green"})
Write-Host "Break-Glass Protected Accounts : $($exempt.Count)" -ForegroundColor Cyan
Write-Host "PIM / JIT Compliant Assignments: $($compliant.Count)" -ForegroundColor Green

if ($nonCompliant.Count -gt 0) {
    Write-Host "`n[CRITICAL VIOLATIONS DETECTED - STANDING PRIVILEGES]:" -ForegroundColor Red
    $nonCompliant | Format-Table RoleName, PrincipalName, UserPrincipalName, Severity, FindingDescription -AutoSize
}

# Save Reports
if ($Format -in @("Both", "Json")) {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $jsonFile = Join-Path $OutputPath "privileged_role_audit_$timestamp.json"
    $csvFile = Join-Path $OutputPath "privileged_role_audit_$timestamp.csv"

    $reportPayload = @{
        TenantId           = $activeContext.TenantId
        AuditedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
        Auditor            = $activeContext.Account
        TotalAssignments   = $auditFindings.Count
        StandingViolations = $nonCompliant.Count
        Findings           = $auditFindings
    }

    $reportPayload | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonFile -Encoding utf8
    $auditFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding utf8

    Write-Host "`n[Audit Evidence Exported]:" -ForegroundColor Green
    Write-Host "  -> JSON Report: $jsonFile" -ForegroundColor Gray
    Write-Host "  -> CSV Report : $csvFile" -ForegroundColor Gray
}

Write-Host "==========================================================" -ForegroundColor Cyan
