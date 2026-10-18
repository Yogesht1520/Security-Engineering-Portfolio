<#
.SYNOPSIS
    Reproducible Microsoft Graph Live Tenant Evidence Exporter & Sanitizer.
.DESCRIPTION
    Connects to Microsoft Entra ID using read-only scopes, retrieves active Conditional
    Access policies, named locations, PIM eligibility schedules, and sign-in log evaluation
    telemetry with full pagination support (@odata.nextLink).
    Deeply sanitizes all tenant GUIDs, personal UPNs, external IPv4/IPv6 addresses before writing
    reproducible evidence artifacts to evidence/live-tenant-state/.
    Tracks per-endpoint success/failure, validates output files on disk, generates a verified
    provenance envelope, and returns explicit COMPLETE, PARTIAL, or FAILED status.
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

. "$PSScriptRoot\evidence_sanitizer.ps1"

$exportResults = [ordered]@{}
$failedExports = [System.Collections.Generic.List[string]]::new()
$verifiedFiles = [System.Collections.Generic.List[string]]::new()

# Helper function to paginate Graph GET requests
function Invoke-PaginatedGraphGet {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InitialUri
    )
    $items = [System.Collections.Generic.List[PSObject]]::new()
    $uri = $InitialUri
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        if ($resp.value) {
            foreach ($v in $resp.value) {
                $items.Add($v)
            }
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    return $items
}

# 2. Export Conditional Access Policies
Write-Host "`n[1/5] Exporting Conditional Access Policies..." -ForegroundColor Cyan
try {
    $caItems = Invoke-PaginatedGraphGet -InitialUri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    $cleanCa = ConvertTo-SanitizedJson -InputObject $caItems
    $outCa = Join-Path $TargetDirectory "conditional-access-policies.json"
    [System.IO.File]::WriteAllText($outCa, $cleanCa, [System.Text.Encoding]::UTF8)

    if ((Test-Path $outCa) -and ((Get-Item $outCa).Length -gt 0)) {
        Write-Host "  -> Saved & Verified: $outCa ($($caItems.Count) policies)" -ForegroundColor Green
        $exportResults["ConditionalAccessPolicies"] = [PSCustomObject]@{ Status = "Success"; Count = $caItems.Count; File = "conditional-access-policies.json" }
        $verifiedFiles.Add("conditional-access-policies.json")
    } else {
        throw "Exported file $outCa is missing or 0 bytes."
    }
} catch {
    Write-Warning "Failed exporting Conditional Access policies: $($_.Exception.Message)"
    $failedExports.Add("ConditionalAccessPolicies")
    $exportResults["ConditionalAccessPolicies"] = [PSCustomObject]@{ Status = "Failed: $($_.Exception.Message)"; Count = 0; File = "conditional-access-policies.json" }
}

# 3. Export Named Locations
Write-Host "`n[2/5] Exporting Named Locations..." -ForegroundColor Cyan
try {
    $locItems = Invoke-PaginatedGraphGet -InitialUri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
    $cleanLoc = ConvertTo-SanitizedJson -InputObject $locItems
    $outLoc = Join-Path $TargetDirectory "named-locations.json"
    [System.IO.File]::WriteAllText($outLoc, $cleanLoc, [System.Text.Encoding]::UTF8)

    if ((Test-Path $outLoc) -and ((Get-Item $outLoc).Length -gt 0)) {
        Write-Host "  -> Saved & Verified: $outLoc ($($locItems.Count) locations)" -ForegroundColor Green
        $exportResults["NamedLocations"] = [PSCustomObject]@{ Status = "Success"; Count = $locItems.Count; File = "named-locations.json" }
        $verifiedFiles.Add("named-locations.json")
    } else {
        throw "Exported file $outLoc is missing or 0 bytes."
    }
} catch {
    Write-Warning "Failed exporting Named Locations: $($_.Exception.Message)"
    $failedExports.Add("NamedLocations")
    $exportResults["NamedLocations"] = [PSCustomObject]@{ Status = "Failed: $($_.Exception.Message)"; Count = 0; File = "named-locations.json" }
}

# 4. Export PIM Eligibility Schedule Instances
Write-Host "`n[3/5] Exporting PIM Eligibility Schedules..." -ForegroundColor Cyan
try {
    $pimItems = Invoke-PaginatedGraphGet -InitialUri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
    $cleanPim = ConvertTo-SanitizedJson -InputObject $pimItems
    $outPim = Join-Path $TargetDirectory "pim-eligibility-schedules.json"
    [System.IO.File]::WriteAllText($outPim, $cleanPim, [System.Text.Encoding]::UTF8)

    if ((Test-Path $outPim) -and ((Get-Item $outPim).Length -gt 0)) {
        Write-Host "  -> Saved & Verified: $outPim ($($pimItems.Count) schedules)" -ForegroundColor Green
        $exportResults["PimEligibilitySchedules"] = [PSCustomObject]@{ Status = "Success"; Count = $pimItems.Count; File = "pim-eligibility-schedules.json" }
        $verifiedFiles.Add("pim-eligibility-schedules.json")
    } else {
        throw "Exported file $outPim is missing or 0 bytes."
    }
} catch {
    Write-Warning "Failed exporting PIM Eligibility Schedules: $($_.Exception.Message)"
    $failedExports.Add("PimEligibilitySchedules")
    $exportResults["PimEligibilitySchedules"] = [PSCustomObject]@{ Status = "Failed: $($_.Exception.Message)"; Count = 0; File = "pim-eligibility-schedules.json" }
}

# 5. Export Sign-In Telemetry Audit Sample (Paginated)
Write-Host "`n[4/5] Exporting Sign-In Telemetry Audit Sample (Paginated)..." -ForegroundColor Cyan
try {
    $signIns = [System.Collections.Generic.List[PSObject]]::new()
    $signInsUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=20"
    $maxPages = 5
    $pagesCount = 0
    do {
        $signInsResp = Invoke-MgGraphRequest -Method GET -Uri $signInsUri -ErrorAction Stop
        if ($signInsResp.value) {
            foreach ($si in $signInsResp.value) { $signIns.Add($si) }
        }
        $pagesCount++
        $signInsUri = if ($pagesCount -lt $maxPages) { $signInsResp.'@odata.nextLink' } else { $null }
    } while ($signInsUri)

    $tId = if ($activeContext) { $activeContext.TenantId } else { $null }
    $cleanSignIns = ConvertTo-SanitizedJson -InputObject $signIns -TenantIdToRedact $tId
    $outSignIns = Join-Path $TargetDirectory "sign-in-telemetry-receipt.json"
    [System.IO.File]::WriteAllText($outSignIns, $cleanSignIns, [System.Text.Encoding]::UTF8)

    if ((Test-Path $outSignIns) -and ((Get-Item $outSignIns).Length -gt 0)) {
        Write-Host "  -> Saved & Verified: $outSignIns ($($signIns.Count) sample events across $pagesCount page(s))" -ForegroundColor Green
        $exportResults["SignInTelemetrySample"] = [PSCustomObject]@{ Status = "Success"; Count = $signIns.Count; File = "sign-in-telemetry-receipt.json"; Scope = "Bounded Paginated Sample ($pagesCount pages)" }
        $verifiedFiles.Add("sign-in-telemetry-receipt.json")
    } else {
        throw "Exported file $outSignIns is missing or 0 bytes."
    }
} catch {
    Write-Warning "Failed exporting Sign-in logs: $($_.Exception.Message)"
    $failedExports.Add("SignInTelemetrySample")
    $exportResults["SignInTelemetrySample"] = [PSCustomObject]@{ Status = "Failed: $($_.Exception.Message)"; Count = 0; File = "sign-in-telemetry-receipt.json" }
}

# Check static evidence files if present
$staticRoleDoc = Join-Path $TargetDirectory "privileged-role-inventory.md"
if ((Test-Path $staticRoleDoc) -and ((Get-Item $staticRoleDoc).Length -gt 0)) {
    $verifiedFiles.Add("privileged-role-inventory.md")
}

# 6. Overall Export Evaluation
$totalEndpointExports = 4
$overallStatus = if ($failedExports.Count -eq 0 -and $verifiedFiles.Count -ge 4) {
    "COMPLETE"
} elseif ($failedExports.Count -lt $totalEndpointExports -and $verifiedFiles.Count -gt 0) {
    "PARTIAL"
} else {
    "FAILED"
}

# 7. Generate Baseline Metadata Envelope
Write-Host "`n[5/5] Generating Live Tenant Baseline Provenance Metadata..." -ForegroundColor Cyan
$baselineEnvelope = [PSCustomObject]@{
    exportTimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    environment        = "Microsoft Entra ID P2 Staging Reference Tenant"
    sanitizationMode   = "Redacted Tenant GUID, Universal UPN/Domain Masks, IPv4/IPv6 CIDR Redaction, and Object GUID Scrambling"
    exportMethod       = "export_tenant_evidence.ps1 via Microsoft Graph API v1.0 (with @odata.nextLink pagination)"
    readOnlyScopes     = $requiredScopes
    overallStatus      = $overallStatus
    verifiedFileCount  = $verifiedFiles.Count
    evidenceFiles      = $verifiedFiles.ToArray()
    exportMetrics      = $exportResults
    failedEndpoints    = $failedExports.ToArray()
}
$outBaseline = Join-Path $TargetDirectory "live-tenant-state.json"
[System.IO.File]::WriteAllText($outBaseline, ($baselineEnvelope | ConvertTo-Json -Depth 6), [System.Text.Encoding]::UTF8)
Write-Host "  -> Saved Provenance Envelope: $outBaseline" -ForegroundColor Green

Write-Host "`n================ LIVE EVIDENCE EXPORT SUMMARY: $overallStatus ================" -ForegroundColor $(if($overallStatus -eq 'COMPLETE'){'Green'}elseif($overallStatus -eq 'PARTIAL'){'Yellow'}else{'Red'})
Write-Host "Overall Export Status : $overallStatus" -ForegroundColor $(if($overallStatus -eq 'COMPLETE'){'Green'}elseif($overallStatus -eq 'PARTIAL'){'Yellow'}else{'Red'})
Write-Host "Verified Files on Disk: $($verifiedFiles.Count)" -ForegroundColor White
Write-Host "Failed Endpoints      : $($failedExports.Count) $(if($failedExports.Count -gt 0){'(' + ($failedExports -join ', ') + ')'})" -ForegroundColor $(if($failedExports.Count -gt 0){'Red'}else{'Green'})
Write-Host "================================================================================" -ForegroundColor $(if($overallStatus -eq 'COMPLETE'){'Green'}elseif($overallStatus -eq 'PARTIAL'){'Yellow'}else{'Red'})

if ($overallStatus -ne "COMPLETE") {
    Write-Error "[EVIDENCE EXPORT $overallStatus] Tenant evidence exporter did not complete cleanly. Failed endpoints: $($failedExports -join ', ')"
    exit 1
}

Write-Host "`n[COMPLETED] Live tenant evidence export and sanitization finished cleanly!" -ForegroundColor Green
