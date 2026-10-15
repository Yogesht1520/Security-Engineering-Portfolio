<#
.SYNOPSIS
    Declarative Drift Detection Engine for Entra ID Conditional Access Policies.
.DESCRIPTION
    Normalizes local Git policy JSON objects and compares them against live tenant policies retrieved
    via Microsoft Graph. Generates structured diffs and identifies out-of-band portal modifications.
.PARAMETER LocalPolicy
    PSObject representing the local desired state.
.PARAMETER LivePolicy
    PSObject representing the live tenant state from Microsoft Graph.
#>

param (
    [Parameter(Mandatory=$false)]
    [PSObject]$LocalPolicy,

    [Parameter(Mandatory=$false)]
    [PSObject]$LivePolicy
)

function Normalize-PolicyObject ($policy) {
    if (-not $policy) { return $null }

    # Clone and strip read-only / dynamic Graph metadata
    $clone = $policy | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $readOnlyProps = @("id", "createdDateTime", "modifiedDateTime", "@odata.context", "@odata.etag", "templateId")
    foreach ($prop in $readOnlyProps) {
        if ($clone.PSObject.Properties[$prop]) {
            [void]$clone.PSObject.Properties.Remove($prop)
        }
    }

    # Normalize state string
    if ($clone.state) {
        $clone.state = $clone.state.ToString().Trim()
    }

    return $clone
}

function Compare-NormalizedPolicies ($desired, $actual) {
    $diffs = @()

    # Compare State
    if ($desired.state -ne $actual.state) {
        $diffs += [PSCustomObject]@{
            Property = "state"
            Expected = $desired.state
            Actual   = $actual.state
            Severity = "HIGH"
        }
    }

    # Compare Grant Controls
    $desiredGrant = $desired.grantControls | ConvertTo-Json -Compress
    $actualGrant = $actual.grantControls | ConvertTo-Json -Compress
    if ($desiredGrant -ne $actualGrant) {
        $diffs += [PSCustomObject]@{
            Property = "grantControls"
            Expected = $desiredGrant
            Actual   = $actualGrant
            Severity = "CRITICAL"
        }
    }

    # Compare Session Controls
    $desiredSession = $desired.sessionControls | ConvertTo-Json -Compress
    $actualSession = $actual.sessionControls | ConvertTo-Json -Compress
    if ($desiredSession -ne $actualSession) {
        $diffs += [PSCustomObject]@{
            Property = "sessionControls"
            Expected = $desiredSession
            Actual   = $actualSession
            Severity = "MEDIUM"
        }
    }

    # Compare Users Scope
    $desiredUsers = $desired.conditions.users | ConvertTo-Json -Compress
    $actualUsers = $actual.conditions.users | ConvertTo-Json -Compress
    if ($desiredUsers -ne $actualUsers) {
        $diffs += [PSCustomObject]@{
            Property = "conditions.users"
            Expected = $desiredUsers
            Actual   = $actualUsers
            Severity = "CRITICAL"
        }
    }

    if ($diffs.Count -eq 0) {
        return @()
    }
    return ,$diffs
}

if ($LocalPolicy -and $LivePolicy) {
    $normLocal = Normalize-PolicyObject $LocalPolicy
    $normLive  = Normalize-PolicyObject $LivePolicy
    $differences = @(Compare-NormalizedPolicies $normLocal $normLive)

    if ($differences.Count -gt 0) {
        Write-Host "`n  [DRIFT DETECTED] Policy: $($normLocal.displayName)" -ForegroundColor Red
        foreach ($d in $differences) {
            Write-Host "    -> Property: $($d.Property) [Severity: $($d.Severity)]" -ForegroundColor Yellow
            Write-Host "       Desired (Git) : $($d.Expected)" -ForegroundColor Green
            Write-Host "       Live (Tenant) : $($d.Actual)" -ForegroundColor Red
        }
        return @{ HasDrift = $true; Diffs = $differences }
    } else {
        Write-Host "  [IN SYNC] Policy: $($normLocal.displayName)" -ForegroundColor Green
        return @{ HasDrift = $false; Diffs = @() }
    }
}
