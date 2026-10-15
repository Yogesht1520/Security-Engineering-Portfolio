<#
.SYNOPSIS
    Centralized Identity Reference Resolver for Entra ID Users.
.DESCRIPTION
    Resolves user UPNs, friendly names, or special keywords into valid Entra ID Directory Object GUIDs.
    Validates that emergency-access accounts exist and fails closed on unresolvable placeholders.
#>

param (
    [Parameter(Mandatory=$true)]
    [string[]]$UserReferences,

    [string]$MappingPath = "$PSScriptRoot\..\..\config\identity-mapping.json",

    [bool]$FailOnUnresolved = $true
)

$specialKeywords = @("All", "None", "GuestsOrExternalUsers")
$guidRegex = "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"

$resolvedIds = @()
$unresolvedUsers = @()

# 1. Load Local Identity Mapping if available
$localMapping = $null
if (Test-Path $MappingPath) {
    try {
        $mappingContent = Get-Content -Path $MappingPath -Raw | ConvertFrom-Json
        $localMapping = $mappingContent.users
    } catch {
        Write-Warning "Could not parse identity mapping at $MappingPath"
    }
}

foreach ($userRef in $UserReferences) {
    if ([string]::IsNullOrWhiteSpace($userRef)) { continue }

    # Pass-through valid Graph special keywords
    if ($specialKeywords -contains $userRef) {
        $resolvedIds += $userRef
        continue
    }

    # Already a valid GUID?
    if ($userRef -match $guidRegex) {
        $resolvedIds += $userRef
        continue
    }

    # Reject known placeholders explicitly
    if ($userRef -match "emergency-admin-id" -or $userRef -match "^<.*>$") {
        $unresolvedUsers += $userRef
        continue
    }

    # Check local mapping
    if ($localMapping -and $localMapping.PSObject.Properties[$userRef]) {
        $mappedId = $localMapping.$userRef
        if ($mappedId -match $guidRegex) {
            $resolvedIds += $mappedId
            continue
        }
    }

    # Check live Graph API if connected
    $graphFound = $false
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            $mgUser = Get-MgUser -Filter "userPrincipalName eq '$userRef' or mailNickname eq '$userRef'" -ErrorAction SilentlyContinue
            if ($mgUser) {
                $resolvedIds += $mgUser.Id
                $graphFound = $true
                continue
            }
        }
    } catch {
        Write-Verbose "Graph lookup failed for $userRef"
    }

    if (-not $graphFound) {
        $unresolvedUsers += $userRef
    }
}

if ($unresolvedUsers.Count -gt 0 -and $FailOnUnresolved) {
    $missingList = $unresolvedUsers -join ", "
    throw "[CRITICAL] Failed to resolve user reference(s): [$missingList]. Placeholders cannot be deployed to Entra ID."
}

return @{
    ResolvedIds     = $resolvedIds
    UnresolvedUsers = $unresolvedUsers
    Success         = ($unresolvedUsers.Count -eq 0)
}
