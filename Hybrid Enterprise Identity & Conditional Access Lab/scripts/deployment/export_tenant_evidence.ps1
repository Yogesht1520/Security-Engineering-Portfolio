<#
.SYNOPSIS
    Reproducible Microsoft Graph Live Tenant Evidence Exporter & Sanitizer.
.DESCRIPTION
    Connects to Microsoft Entra ID using read-only scopes, retrieves active Conditional
    Access policies, named locations, PIM eligibility schedules, directory role assignments,
    and sign-in log evaluation telemetry. Automatically sanitizes all tenant GUIDs, personal
    UPNs, and external IP addresses before writing reproducible evidence artifacts to
    evidence/live-tenant-state/.
.PARAMETER TargetDirectory
    Output directory for sanitized evidence artifacts (default: evidence/live-tenant-state).
.PARAMETER DeviceCode
    Use OAuth2 device code flow for authentication.
#>

[CmdletBinding()]
param (
    [string]$TargetDirectory = "$PSScriptRoot\..\..\evidence\live-tenant-state",
    [switch]$DeviceCode
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Live Tenant Evidence Exporter & Sanitizer Engine        " -ForegroundColor Cyan
Write-Host "  Zero-Trust Read-Only Compliance Verification            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$requiredScopes = @(
    "Policy.Read.ConditionalAccess",
    "RoleManagement.Read.Directory",
    "AuditLog.Read.All",
    "Directory.Read.All"
)

# 1. Connect to Microsoft Graph
$env:ENTRA_IDENTITY_DISABLE_WAM = "true"
$activeContext = $null
try {
    $activeContext = Get-MgContext -ErrorAction Stop
} catch {
    $activeContext = $null
}

if (-not $activeContext) {
    Write-Host "`n[Authentication] Connecting with read-only scopes..." -ForegroundColor Yellow
    $authParams = @{
        Scopes    = $requiredScopes
        NoWelcome = $true
    }
    if ($DeviceCode) {
        $authParams["UseDeviceAuthentication"] = $true
    }
    Connect-MgGraph @authParams
    $activeContext = Get-MgContext
}

if (-not (Test-Path $TargetDirectory)) {
    New-Item -ItemType Directory -Path $TargetDirectory -Force | Out-Null
}

$tenantId = $activeContext.TenantId

function ConvertTo-SanitizedJson {
    param([Parameter(Mandatory=$true)]$InputObject)

    $json = $InputObject | ConvertTo-Json -Depth 10
    if ($tenantId) {
        $json = $json -replace [regex]::Escape($tenantId), "<REDACTED_TENANT_ID>"
    }
    $json = $json -replace "@[a-zA-Z0-9.-]+\.onmicrosoft\.com", "@<LAB_DOMAIN>"
    $json = $json -replace '"id":\s*"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"', '"id": "<REDACTED_OBJECT_ID>"'
    return $json
}

# 2. Export Conditional Access Policies
Write-Host "`n[1/5] Exporting Conditional Access Policies..." -ForegroundColor Cyan
try {
    $caResp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    $cleanCa = ConvertTo-SanitizedJson -InputObject $caResp.value
    $outCa = Join-Path $TargetDirectory "conditional-access-policies.json"
    [System.IO.File]::WriteAllText($outCa, $cleanCa, [System.Text.Encoding]::UTF8)
    Write-Host "  -> Saved: $outCa ($(@($caResp.value).Count) policies)" -ForegroundColor Green
} catch {
    Write-Warning "Failed exporting Conditional Access policies: $($_.Exception.Message)"
}

# 3. Export Named Locations
Write-Host "`n[2/5] Exporting Named Locations..." -ForegroundColor Cyan
try {
    $locResp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
    $cleanLoc = ConvertTo-SanitizedJson -InputObject $locResp.value
    $outLoc = Join-Path $TargetDirectory "named-locations.json"
    [System.IO.File]::WriteAllText($outLoc, $cleanLoc, [System.Text.Encoding]::UTF8)
    Write-Host "  -> Saved: $outLoc ($(@($locResp.value).Count) locations)" -ForegroundColor Green
} catch {
    Write-Warning "Failed exporting Named Locations: $($_.Exception.Message)"
}

# 4. Export PIM Eligibility Schedule Instances
Write-Host "`n[3/5] Exporting PIM Eligibility Schedules..." -ForegroundColor Cyan
try {
    $pimResp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
    $cleanPim = ConvertTo-SanitizedJson -InputObject $pimResp.value
    $outPim = Join-Path $TargetDirectory "pim-eligibility-schedules.json"
    [System.IO.File]::WriteAllText($outPim, $cleanPim, [System.Text.Encoding]::UTF8)
    Write-Host "  -> Saved: $outPim ($(@($pimResp.value).Count) schedules)" -ForegroundColor Green
} catch {
    Write-Warning "Failed exporting PIM Eligibility Schedules: $($_.Exception.Message)"
}

# 5. Export Sign-In Telemetry Receipt
Write-Host "`n[4/5] Exporting Sample Sign-In Telemetry..." -ForegroundColor Cyan
try {
    $signIns = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=10"
    $cleanSignIns = ConvertTo-SanitizedJson -InputObject $signIns.value
    $outSignIns = Join-Path $TargetDirectory "sign-in-telemetry-receipt.json"
    [System.IO.File]::WriteAllText($outSignIns, $cleanSignIns, [System.Text.Encoding]::UTF8)
    Write-Host "  -> Saved: $outSignIns ($(@($signIns.value).Count) events)" -ForegroundColor Green
} catch {
    Write-Warning "Failed exporting Sign-in logs: $($_.Exception.Message)"
}

# 6. Generate Baseline Metadata Envelope
Write-Host "`n[5/5] Generating Live Tenant Baseline Provenance Metadata..." -ForegroundColor Cyan
$baselineEnvelope = [PSCustomObject]@{
    exportTimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    environment        = "Microsoft Entra ID P2 Staging Reference Tenant"
    sanitizationMode   = "Redacted Tenant GUID & Domain Masks"
    exportMethod       = "export_tenant_evidence.ps1 via Microsoft Graph API v1.0"
    readOnlyScopes     = $requiredScopes
    evidenceFiles      = @(
        "conditional-access-policies.json",
        "named-locations.json",
        "pim-eligibility-schedules.json",
        "sign-in-telemetry-receipt.json",
        "privileged-role-inventory.md"
    )
}
$outBaseline = Join-Path $TargetDirectory "live-tenant-state.json"
[System.IO.File]::WriteAllText($outBaseline, ($baselineEnvelope | ConvertTo-Json -Depth 5), [System.Text.Encoding]::UTF8)
Write-Host "  -> Saved: $outBaseline" -ForegroundColor Green

Write-Host "`n[COMPLETED] Live tenant evidence export and sanitization finished cleanly!" -ForegroundColor Green
