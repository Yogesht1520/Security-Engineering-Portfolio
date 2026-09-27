<#
.SYNOPSIS
    Declarative Identity-as-Code: Deploys Conditional Access policies from JSON definitions.
.DESCRIPTION
    Reads JSON policy definitions from the policies/ directory and deploys them to Microsoft Entra ID
    using the Microsoft Graph SDK. Supports idempotency (create or update) and CI/CD validation mode.
.PARAMETER PoliciesPath
    Path to directory containing policy JSON files.
.PARAMETER ValidateOnly
    If set, validates policy JSON schemas without pushing changes to Entra ID.
#>

param (
    [string]$PoliciesPath = "$PSScriptRoot\..\policies",
    [switch]$ValidateOnly,
    [string]$TenantId
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Conditional Access as Code (Identity-as-Code Pipeline) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Validate Policy Directory
$resolvedPath = Resolve-Path $PoliciesPath -ErrorAction SilentlyContinue
if (-not $resolvedPath) {
    Write-Error "Policies directory not found at $PoliciesPath"
    exit 1
}

$policyFiles = Get-ChildItem -Path $resolvedPath -Filter "*.json"
Write-Host "`nFound $($policyFiles.Count) declarative policy definition(s) in $resolvedPath" -ForegroundColor White

# 2. Syntax & Schema Pre-Flight Check
$parsedPolicies = @()
foreach ($file in $policyFiles) {
    try {
        $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        if (-not $content.displayName -or -not $content.conditions) {
            throw "Missing required top-level keys ('displayName', 'conditions')."
        }
        $parsedPolicies += @{
            File    = $file.Name
            Payload = $content
        }
        Write-Host "  [OK] Validated JSON schema: $($file.Name)" -ForegroundColor Green
    } catch {
        Write-Error "  [FAILED] Invalid schema in $($file.Name): $($_.Exception.Message)"
        exit 1
    }
}

if ($ValidateOnly) {
    Write-Host "`n[CI/CD Mode] Validation passed for all policy definitions. Exiting without deployment." -ForegroundColor Yellow
    exit 0
}

# 3. Connect to Microsoft Graph
Write-Host "`nConnecting to Microsoft Graph (Scope: Policy.ReadWrite.ConditionalAccess)..." -ForegroundColor Cyan
if ($TenantId) {
    Connect-MgGraph -TenantId $TenantId -Scopes "Policy.ReadWrite.ConditionalAccess", "Group.Read.All" -NoWelcome
} else {
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess", "Group.Read.All" -NoWelcome
}

# 4. Resolve Environment Context (Groups & Named Locations)
Write-Host "`nResolving dynamic tenant identifiers..." -ForegroundColor Cyan
$groups = Get-MgGroup -All
$groupMap = @{}
foreach ($g in $groups) { $groupMap[$g.DisplayName] = $g.Id }

# 5. Idempotent Policy Deployment
Write-Host "`nApplying Policies to Microsoft Entra ID..." -ForegroundColor Cyan
$existingPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -OutputType PSObject

foreach ($p in $parsedPolicies) {
    $displayName = $p.Payload.displayName
    $existing = $existingPolicies.value | Where-Object { $_.displayName -eq $displayName }

    # Deep-resolve friendly group names to current tenant IDs
    if ($p.Payload.conditions.users.includeGroups) {
        $resolvedGroupIds = @()
        foreach ($grpName in $p.Payload.conditions.users.includeGroups) {
            if ($groupMap.ContainsKey($grpName)) {
                $resolvedGroupIds += $groupMap[$grpName]
            } else {
                $resolvedGroupIds += $grpName
            }
        }
        $p.Payload.conditions.users.includeGroups = $resolvedGroupIds
    }

    $jsonBody = $p.Payload | ConvertTo-Json -Depth 10

    if ($existing) {
        Write-Host "  [Updating] $displayName (ID: $($existing.id))..." -ForegroundColor Yellow
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)"
        Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $jsonBody -ContentType "application/json" | Out-Null
        Write-Host "  -> Successfully updated." -ForegroundColor Green
    } else {
        Write-Host "  [Creating] $displayName..." -ForegroundColor Cyan
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        $created = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $jsonBody -ContentType "application/json"
        Write-Host "  -> Successfully created (ID: $($created.id))." -ForegroundColor Green
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  Deployment complete! All policies synchronized.        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
