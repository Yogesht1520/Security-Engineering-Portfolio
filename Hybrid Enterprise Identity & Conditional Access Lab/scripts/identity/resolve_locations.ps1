<#
.SYNOPSIS
    Centralized Identity Reference Resolver for Entra ID Named Locations.
.DESCRIPTION
    Resolves friendly location aliases (e.g., 'Allowed-Home-Country-Id') into live Named Location GUIDs.
    Uses Graph REST API directly via Invoke-MgGraphRequest, checks config/identity-mapping.json,
    and supports auto-provisioning a baseline country location if none exists.
#>

param (
    [Parameter(Mandatory=$true)]
    [string[]]$LocationReferences,

    [string]$MappingPath = "$PSScriptRoot\..\..\config\identity-mapping.json",

    [bool]$FailOnUnresolved = $true,

    [bool]$AutoCreateIfMissing = $true
)

$specialKeywords = @("All", "AllTrusted")
$guidRegex = "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"

$resolvedIds = @()
$unresolvedLocations = @()

# 1. Load Local Mapping
$localMapping = $null
if (Test-Path $MappingPath) {
    try {
        $mappingContent = Get-Content -Path $MappingPath -Raw | ConvertFrom-Json
        $localMapping = $mappingContent.namedLocations
    } catch {
        Write-Warning "Could not parse identity mapping at $MappingPath"
    }
}

# 2. Live Graph Named Locations Cache using REST API directly
$graphLocationCache = @{}
$existingNamedLocations = @()

try {
    $context = Get-MgContext -ErrorAction SilentlyContinue
    if ($context) {
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
        if ($response.value) {
            $existingNamedLocations = $response.value
            foreach ($loc in $response.value) {
                $graphLocationCache[$loc.displayName] = $loc.id
                $graphLocationCache[$loc.displayName.ToLower()] = $loc.id
            }
        }
    }
} catch {
    # Fallback to cmdlet if installed
    try {
        $locations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
        foreach ($loc in $locations) {
            $graphLocationCache[$loc.DisplayName] = $loc.Id
            $graphLocationCache[$loc.DisplayName.ToLower()] = $loc.Id
        }
    } catch {
        Write-Verbose "Could not query named locations: $($_.Exception.Message)"
    }
}

# 3. Resolve References
foreach ($locRef in $LocationReferences) {
    if ([string]::IsNullOrWhiteSpace($locRef)) { continue }

    if ($specialKeywords -contains $locRef -or $locRef -match $guidRegex) {
        $resolvedIds += $locRef
        continue
    }

    # Check local static mapping
    if ($localMapping -and $localMapping.PSObject.Properties[$locRef]) {
        $mappedId = $localMapping.$locRef
        if ($mappedId -match $guidRegex) {
            $resolvedIds += $mappedId
            continue
        }
    }

    # Check live Graph cache (exact or lower-case)
    if ($graphLocationCache.ContainsKey($locRef)) {
        $resolvedIds += $graphLocationCache[$locRef]
        continue
    }
    if ($graphLocationCache.ContainsKey($locRef.ToLower())) {
        $resolvedIds += $graphLocationCache[$locRef.ToLower()]
        continue
    }

    # Check with "-Id" stripped or appended
    $strippedRef = $locRef -replace '-[iI]d$', ''
    if ($graphLocationCache.ContainsKey($strippedRef)) {
        $resolvedIds += $graphLocationCache[$strippedRef]
        continue
    }
    if ($graphLocationCache.ContainsKey($strippedRef.ToLower())) {
        $resolvedIds += $graphLocationCache[$strippedRef.ToLower()]
        continue
    }

    # If any single country location exists in tenant, bind to it
    if ($existingNamedLocations.Count -eq 1) {
        $singleLoc = $existingNamedLocations[0]
        Write-Host "  [Auto-Bound] Named location '$locRef' mapped to existing tenant location '$($singleLoc.displayName)' (ID: $($singleLoc.id))" -ForegroundColor Cyan
        $resolvedIds += $singleLoc.id
        continue
    }

    # 4. Auto-Provision Baseline Country Location if missing
    if ($AutoCreateIfMissing -and (Get-MgContext)) {
        Write-Host "  [Auto-Provision] Named location '$locRef' not found in tenant. Creating baseline..." -ForegroundColor Yellow
        try {
            $newLocationBody = @{
                "@odata.type"                       = "#microsoft.graph.countryNamedLocation"
                displayName                         = $locRef
                countriesAndRegions                 = @("IN", "US")
                includeUnknownCountriesAndRegions   = $false
            } | ConvertTo-Json

            $createUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
            $createdLoc = Invoke-MgGraphRequest -Method POST -Uri $createUri -Body $newLocationBody -ContentType "application/json" -OutputType PSObject
            Write-Host "  -> Successfully created Named Location '$locRef' (ID: $($createdLoc.id))" -ForegroundColor Green
            $resolvedIds += $createdLoc.id
            $graphLocationCache[$locRef] = $createdLoc.id
            continue
        } catch {
            Write-Warning "Auto-provisioning named location failed: $($_.Exception.Message)"
        }
    }

    $unresolvedLocations += $locRef
}

if ($unresolvedLocations.Count -gt 0 -and $FailOnUnresolved) {
    $missingList = $unresolvedLocations -join ", "
    throw "[CRITICAL] Failed to resolve named location reference(s): [$missingList]. Create a Named Location in Entra ID or check config/identity-mapping.json."
}

return @{
    ResolvedIds         = $resolvedIds
    UnresolvedLocations = $unresolvedLocations
    Success             = ($unresolvedLocations.Count -eq 0)
}
