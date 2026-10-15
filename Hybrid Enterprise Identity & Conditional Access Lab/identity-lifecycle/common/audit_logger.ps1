<#
.SYNOPSIS
    Shared Audit Logging Engine for Enterprise Identity Lifecycle (JML).
.DESCRIPTION
    Provides standardized, structured JSON/JSONL audit logging for all Joiner,
    Mover, and Leaver events. Ensures complete auditability for compliance (SOC 2, ISO 27001).
#>

function Write-LifecycleAuditLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("JOINER", "MOVER", "LEAVER", "SECURITY_ALERT")]
        [string]$EventType,

        [Parameter(Mandatory=$true)]
        [string]$TargetUserPrincipalName,

        [Parameter(Mandatory=$false)]
        [string]$TargetUserId = "",

        [Parameter(Mandatory=$true)]
        [string]$Action,

        [Parameter(Mandatory=$true)]
        [ValidateSet("SUCCESS", "WARNING", "FAILURE")]
        [string]$Status,

        [Parameter(Mandatory=$false)]
        [hashtable]$Details = @{},

        [Parameter(Mandatory=$false)]
        [string]$Initiator = "$($env:USERNAME)@local",

        [Parameter(Mandatory=$false)]
        [string]$LogDirectory = "$PSScriptRoot\..\..\reports"
    )

    $timestampUtc = (Get-Date).ToUniversalTime().ToString("o")

    $auditEntry = [PSCustomObject]@{
        TimestampUtc            = $timestampUtc
        EventType               = $EventType
        TargetUserPrincipalName = $TargetUserPrincipalName
        TargetUserId            = $TargetUserId
        Action                  = $Action
        Status                  = $Status
        Initiator               = $Initiator
        Details                 = $Details
    }

    # Colorized Console Logging
    $color = switch ($Status) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "FAILURE" { "Red" }
        Default   { "White" }
    }
    Write-Host "[$timestampUtc] [$EventType] [$Status] $Action ($TargetUserPrincipalName)" -ForegroundColor $color

    # File Logging (JSON Lines and Structured Audit Trail)
    try {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
        }

        $auditLogFile = Join-Path $LogDirectory "lifecycle_audit.jsonl"
        $jsonLine = $auditEntry | ConvertTo-Json -Compress -Depth 10
        Add-Content -Path $auditLogFile -Value $jsonLine -Encoding utf8
    } catch {
        Write-Warning "Failed writing audit log to file: $($_.Exception.Message)"
    }

    return $auditEntry
}

