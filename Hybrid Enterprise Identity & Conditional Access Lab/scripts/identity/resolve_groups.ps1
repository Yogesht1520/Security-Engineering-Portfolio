<#
.SYNOPSIS
    Centralized Identity Reference Resolver for Entra ID Security Groups.
.DESCRIPTION
    Resolves friendly security group display names (e.g., 'SEC-Admins') into valid Entra ID
    Directory Object GUIDs. Checks config/identity-mapping.json first, falls back to live Graph API,
    and fails closed if any group cannot be resolved.
.PARAMETER GroupNames
    Array of group names or GUIDs to resolve.
.PARAMETER MappingPath
    Path to local identity-mapping.json.
.PARAMETER FailOnUnresolved
    If true (default), throws an error when any group reference cannot be resolved.
#>

param (
    [Parameter(Mandatory=$true)]
    [string[]]$GroupNames,

    [string]$MappingPath = "$PSScriptRoot\..\..\config\identity-mapping.json",

    [bool]$FailOnUnresolved = $true
)

$resolvedIds = @()
$unresolvedNames = @()

# 1. Load Local Identity Mapping if available
$localMapping = $null
if (Test-Path $MappingPath) {
    try {
        $mappingContent = Get-Content -Path $MappingPath -Raw | ConvertFrom-Json
        $localMapping = $mappingContent.groups
    } catch {
        Write-Warning "Could not parse identity mapping at $MappingPath : $($_.Exception.Message)"
    }
}

# 2. Build In-Memory Cache from Microsoft Graph if connected
$graphGroupCache = @{}
$ambiguousGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$isGraphConnected = $false
try {
    $context = $null
    try {
        $context = Get-MgContext -ErrorAction Stop
    } catch {
        $context = $null
    }
    if ($context) {
        $isGraphConnected = $true
        # Query groups with pagination support
        $allGroups = Get-MgGroup -All -Property "id,displayName" -ErrorAction Stop
        foreach ($g in $allGroups) {
            if ($graphGroupCache.ContainsKey($g.DisplayName)) {
                $ambiguousGroups.Add($g.DisplayName) | Out-Null
            } else {
                $graphGroupCache[$g.DisplayName] = $g.Id
            }
        }
    }
} catch {
    Write-Verbose "Graph not connected or error retrieving groups: $($_.Exception.Message)"
}

# 3. Resolve Each Reference
$guidRegex = "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"

foreach ($name in $GroupNames) {
    if ([string]::IsNullOrWhiteSpace($name)) { continue }

    # Already a valid GUID?
    if ($name -match $guidRegex) {
        $resolvedIds += $name
        continue
    }

    # Check local static mapping file
    if ($localMapping -and $localMapping.PSObject.Properties[$name]) {
        $mappedId = $localMapping.$name
        if ($mappedId -match $guidRegex) {
            $resolvedIds += $mappedId
            continue
        }
    }

    # Reject Ambiguous Groups in Directory
    if ($ambiguousGroups.Contains($name)) {
        throw "[AMBIGUOUS GROUP ERROR] Multiple groups share display name '$name' in directory. Cannot resolve unambiguous identity GUID. Configure an explicit mapping in identity-mapping.json or use immutable object ID."
    }

    # Check live Graph cache
    if ($isGraphConnected -and $graphGroupCache.ContainsKey($name)) {
        $resolvedIds += $graphGroupCache[$name]
        continue
    }

    # Reference could not be resolved
    $unresolvedNames += $name
}

if ($unresolvedNames.Count -gt 0 -and $FailOnUnresolved) {
    $missingList = $unresolvedNames -join ", "
    throw "[CRITICAL] Failed to resolve security group reference(s): [$missingList]. Deployment aborted to prevent invalid policy push."
}

return @{
    ResolvedIds     = $resolvedIds
    UnresolvedNames = $unresolvedNames
    Success         = ($unresolvedNames.Count -eq 0)
}
