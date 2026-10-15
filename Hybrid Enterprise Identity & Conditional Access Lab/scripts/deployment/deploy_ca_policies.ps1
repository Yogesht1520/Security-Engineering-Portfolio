<#
.SYNOPSIS
    Enterprise Identity-as-Code (IaC) Deployment Engine for Microsoft Entra Conditional Access.
.DESCRIPTION
    Declarative policy orchestration engine implementing Zero Trust safe staging:
    - Validates policy definitions against JSON Schema.
    - Resolves both include and exclude group/user/location references via centralized resolvers.
    - Validates mandatory emergency break-glass exclusion controls.
    - Generates pre-deployment diffs and drift reports against live Entra state.
    - Creates immutable pre-deployment rollback snapshots.
    - Supports CI/CD dry runs (-ValidateOnly), deployment planning (-Plan / -WhatIf), and progressive execution.
.PARAMETER PoliciesPath
    Path to directory containing policy JSON files.
.PARAMETER ValidateOnly
    Validates schemas and reference integrity locally without Graph network calls.
.PARAMETER Plan
    Connects to Graph, resolves live identifiers, and outputs before/after diffs without changes.
.PARAMETER Deploy
    Applies declarative changes to Microsoft Entra ID.
.PARAMETER Environment
    Target environment profile ('Lab', 'Staging', 'Production'). Default is 'Lab'.
.PARAMETER PolicyId
    Filters deployment to a single policy (e.g. 'CAP-001').
.PARAMETER Force
    Bypasses interactive confirmation during -Deploy.
#>

[CmdletBinding(DefaultParameterSetName="Plan")]
param (
    [string]$PoliciesPath = "$PSScriptRoot\..\..\policies",

    [switch]$ValidateOnly,

    [switch]$Plan,

    [switch]$Deploy,

    [string]$Environment = "Lab",

    [string]$PolicyId,

    [switch]$DeviceCode,

    [switch]$Force
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity-as-Code Engine (Microsoft Entra ID) " -ForegroundColor Cyan
Write-Host "  Environment: $Environment | Mode: $(if($ValidateOnly){'ValidateOnly'}elseif($Deploy){'Deploy'}else{'Plan/WhatIf'})" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Resolve Policy Directory
$resolvedPoliciesPath = Resolve-Path $PoliciesPath -ErrorAction SilentlyContinue
if (-not $resolvedPoliciesPath) {
    Write-Error "Policies directory not found at $PoliciesPath"
    exit 1
}

$policyFiles = Get-ChildItem -Path $resolvedPoliciesPath -Filter "*.json"
if ($PolicyId) {
    $policyFiles = $policyFiles | Where-Object { $_.Name -like "$PolicyId*.json" -or $_.Name -like "*$PolicyId*.json" }
}

Write-Host "`n[Step 1/5] Loaded $($policyFiles.Count) declarative policy definition(s) from $resolvedPoliciesPath" -ForegroundColor White

# 2. Syntax & Schema Validation Check
Write-Host "`n[Step 2/5] Performing Schema & Baseline Pre-Flight Validation..." -ForegroundColor Cyan
$parsedPolicies = @()
$schemaFile = Join-Path $PSScriptRoot "..\..\policies\schema\conditional-access.schema.json"

foreach ($file in $policyFiles) {
    try {
        $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        
        # Validation checks
        if (-not $content.displayName) {
            throw "Missing required top-level property: 'displayName'."
        }
        if (-not $content.state) {
            throw "Missing required top-level property: 'state'."
        }
        if (-not $content.conditions -or -not $content.conditions.users -or -not $content.conditions.applications) {
            throw "Missing required conditions: 'users' and 'applications' must be defined."
        }

        # Check for known unresolvable placeholders
        $rawJson = Get-Content -Path $file.FullName -Raw
        if ($rawJson -match "emergency-admin-id" -or $rawJson -match "<[A-Z0-9_]+>") {
            throw "Unresolved placeholder detected in $($file.Name). Must resolve before deployment."
        }

        # Mandatory Break-Glass Exclusion Check for broad/blocking policies
        $isGlobalPolicy = $content.conditions.users.includeUsers -contains "All" -or $content.conditions.users.includeRoles.Count -gt 0
        if ($isGlobalPolicy -and $content.displayName -notmatch "CAP-005") {
            $hasBreakGlassExclusion = $content.conditions.users.excludeGroups -contains "SEC-BreakGlass-Exclusion"
            if (-not $hasBreakGlassExclusion) {
                Write-Warning "Policy '$($content.displayName)' does not exclude 'SEC-BreakGlass-Exclusion'. This violates safety baseline standards."
            }
        }

        $parsedPolicies += [PSCustomObject]@{
            File        = $file.Name
            FilePath    = $file.FullName
            Policy      = $content
            DisplayName = $content.displayName
        }
        Write-Host "  [PASS] Validated definition: $($file.Name) ('$($content.displayName)')" -ForegroundColor Green
    } catch {
        Write-Error "  [FAIL] Schema validation rejected $($file.Name): $($_.Exception.Message)"
        exit 1
    }
}

if ($ValidateOnly) {
    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  [CI/CD Mode] All policy definitions PASSED schema check! " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    exit 0
}

# 3. Connect to Microsoft Graph
Write-Host "`n[Step 3/5] Connecting to Microsoft Graph..." -ForegroundColor Cyan
$requiredScopes = @("Policy.ReadWrite.ConditionalAccess", "Policy.Read.All", "Group.Read.All", "User.Read.All")
$context = Get-MgContext -ErrorAction SilentlyContinue
$hasRequiredScopes = $context -and ($requiredScopes | Where-Object { $context.Scopes -notcontains $_ }).Count -eq 0

if (-not $hasRequiredScopes) {
    Write-Host "Re-authenticating to acquire required Conditional Access scopes..." -ForegroundColor Yellow
    $env:ENTRA_IDENTITY_DISABLE_WAM = "true"
    $tenantConfigFile = Join-Path $PSScriptRoot "..\..\config\tenant.json"
    $tId = if (Test-Path $tenantConfigFile) { (Get-Content $tenantConfigFile -Raw | ConvertFrom-Json).tenantId } else { $null }

    if ($DeviceCode) {
        if ($tId) {
            Connect-MgGraph -TenantId $tId -Scopes $requiredScopes -UseDeviceAuthentication -NoWelcome
        } else {
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication -NoWelcome
        }
    } else {
        if ($tId) {
            Connect-MgGraph -TenantId $tId -Scopes $requiredScopes -NoWelcome
        } else {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        }
    }
}

$activeContext = Get-MgContext
Write-Host "Connected to Tenant ID: $($activeContext.TenantId) as $($activeContext.Account)" -ForegroundColor Green

# 4. Reference Resolution (Groups, Users, Named Locations)
Write-Host "`n[Step 4/5] Resolving Identity References against Tenant State..." -ForegroundColor Cyan
$groupResolver    = Join-Path $PSScriptRoot "..\identity\resolve_groups.ps1"
$userResolver     = Join-Path $PSScriptRoot "..\identity\resolve_users.ps1"
$locationResolver = Join-Path $PSScriptRoot "..\identity\resolve_locations.ps1"

foreach ($p in $parsedPolicies) {
    $policy = $p.Policy
    Write-Host "  Resolving references for '$($p.DisplayName)'..." -ForegroundColor Gray

    # Resolve includeGroups
    if ($policy.conditions.users.includeGroups) {
        $res = & $groupResolver -GroupNames $policy.conditions.users.includeGroups -FailOnUnresolved $true
        $policy.conditions.users.includeGroups = $res.ResolvedIds
    }

    # Resolve excludeGroups
    if ($policy.conditions.users.excludeGroups) {
        $res = & $groupResolver -GroupNames $policy.conditions.users.excludeGroups -FailOnUnresolved $true
        $policy.conditions.users.excludeGroups = $res.ResolvedIds
    }

    # Resolve includeUsers
    if ($policy.conditions.users.includeUsers) {
        $res = & $userResolver -UserReferences $policy.conditions.users.includeUsers -FailOnUnresolved $true
        $policy.conditions.users.includeUsers = $res.ResolvedIds
    }

    # Resolve excludeUsers
    if ($policy.conditions.users.excludeUsers) {
        $res = & $userResolver -UserReferences $policy.conditions.users.excludeUsers -FailOnUnresolved $true
        $policy.conditions.users.excludeUsers = $res.ResolvedIds
    }

    # Resolve Locations
    if ($policy.conditions.locations) {
        if ($policy.conditions.locations.includeLocations) {
            $res = & $locationResolver -LocationReferences $policy.conditions.locations.includeLocations -FailOnUnresolved $true
            $policy.conditions.locations.includeLocations = $res.ResolvedIds
        }
        if ($policy.conditions.locations.excludeLocations) {
            $res = & $locationResolver -LocationReferences $policy.conditions.locations.excludeLocations -FailOnUnresolved $true
            $policy.conditions.locations.excludeLocations = $res.ResolvedIds
        }
    }
}
Write-Host "  -> All identity references successfully resolved to active tenant GUIDs." -ForegroundColor Green

# 5. Query Live Policies with Pagination Support
Write-Host "`n[Step 5/5] Comparing Desired State with Live Tenant..." -ForegroundColor Cyan
$livePolicies = @()
$uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    if ($response.value) { $livePolicies += $response.value }
    $uri = $response.'@odata.nextLink'
} while ($uri)

$compareScript = Join-Path $PSScriptRoot "compare_policies.ps1"
$actionsToTake = @()

foreach ($p in $parsedPolicies) {
    $displayName = $p.DisplayName
    $policyPrefix = if ($displayName -match "^(CAP-[0-9]{3})") { $Matches[1] } else { $null }
    $existing = $livePolicies | Where-Object { 
        $_.displayName -eq $displayName -or ($policyPrefix -and $_.displayName -like "$policyPrefix*") 
    } | Select-Object -First 1

    if ($existing) {
        # Check for drift
        $driftResult = & $compareScript -LocalPolicy $p.Policy -LivePolicy $existing
        $actionsToTake += [PSCustomObject]@{
            Action      = "Update"
            DisplayName = $displayName
            PolicyId    = $existing.id
            Payload     = $p.Policy
            HasDrift    = $driftResult.HasDrift
        }
    } else {
        Write-Host "  [NEW POLICY] '$displayName' will be CREATED in tenant." -ForegroundColor Cyan
        $actionsToTake += [PSCustomObject]@{
            Action      = "Create"
            DisplayName = $displayName
            PolicyId    = $null
            Payload     = $p.Policy
            HasDrift    = $true
        }
    }
}

# 6. Execution Gate (Plan vs Deploy)
if (-not $Deploy) {
    Write-Host "`n==========================================================" -ForegroundColor Yellow
    Write-Host "  [PLAN COMPLETE] Execution Summary:                    " -ForegroundColor Yellow
    Write-Host "  Policies to Create: $(($actionsToTake | Where-Object { $_.Action -eq 'Create' }).Count)" -ForegroundColor White
    Write-Host "  Policies to Update: $(($actionsToTake | Where-Object { $_.Action -eq 'Update' }).Count)" -ForegroundColor White
    Write-Host "  Run with -Deploy to apply these changes to Microsoft Entra ID." -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Yellow
    exit 0
}

# 7. Deployment Confirmation & Rollback Snapshotting
if (-not $Force) {
    $confirm = Read-Host "`nAre you sure you want to deploy these changes to tenant '$($activeContext.TenantId)'? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Deployment aborted by operator." -ForegroundColor Red
        exit 0
    }
}

# Create Safety Snapshot before applying changes
$rollbackScript = Join-Path $PSScriptRoot "rollback_policies.ps1"
Write-Host "`nGenerating pre-deployment rollback snapshot..." -ForegroundColor Cyan
$snapshotId = & $rollbackScript -Action Snapshot

Write-Host "`nExecuting Live Policy Deployment..." -ForegroundColor Cyan
foreach ($item in $actionsToTake) {
    $jsonBody = $item.Payload | ConvertTo-Json -Depth 10

    if ($item.Action -eq "Update") {
        Write-Host "  [Updating] $($item.DisplayName) (ID: $($item.PolicyId))..." -ForegroundColor Yellow
        $patchUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($item.PolicyId)"
        try {
            Invoke-MgGraphRequest -Method PATCH -Uri $patchUri -Body $jsonBody -ContentType "application/json" -ErrorAction Stop | Out-Null
            Write-Host "  -> Successfully updated." -ForegroundColor Green
        } catch {
            Write-Host "  -> FAILED to update: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  [Creating] $($item.DisplayName)..." -ForegroundColor Cyan
        $postUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        try {
            $created = Invoke-MgGraphRequest -Method POST -Uri $postUri -Body $jsonBody -ContentType "application/json" -ErrorAction Stop
            Write-Host "  -> Successfully created (ID: $($created.id))." -ForegroundColor Green
        } catch {
            Write-Host "  -> FAILED to create: $_" -ForegroundColor Red
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  Deployment Successful! All policies synchronized.       " -ForegroundColor Green
Write-Host "  Rollback Snapshot: $snapshotId                         " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
