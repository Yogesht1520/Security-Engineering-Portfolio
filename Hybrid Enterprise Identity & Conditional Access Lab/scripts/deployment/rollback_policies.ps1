<#
.SYNOPSIS
    Automated Snapshot and Rollback Engine for Conditional Access Policies.
.DESCRIPTION
    Provides safety mechanisms for policy deployments:
    - Creates immutable pre-deployment snapshots of live Entra ID CA policies.
    - Restores previous policy states in the event of an outage, unintended lockout, or regression.
.PARAMETER Action
    'Snapshot', 'Restore', or 'List'.
.PARAMETER SnapshotId
    Timestamp/ID of the snapshot to restore (defaults to most recent).
.PARAMETER SnapshotsDir
    Directory where snapshots are preserved.
#>

param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Snapshot", "Restore", "List")]
    [string]$Action = "Snapshot",

    [string]$SnapshotId,

    [string]$SnapshotsDir = "$PSScriptRoot\..\..\snapshots"
)

if (-not (Test-Path $SnapshotsDir)) {
    New-Item -ItemType Directory -Path $SnapshotsDir -Force | Out-Null
}

function Save-TenantSnapshot {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $targetDir = Join-Path $SnapshotsDir $timestamp
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null

    Write-Host "`n[Safety Snapshot] Exporting current live Entra ID Conditional Access state..." -ForegroundColor Cyan
    try {
        # Query all live policies handling pagination
        $policies = @()
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
            if ($response.value) { $policies += $response.value }
            $uri = $response.'@odata.nextLink'
        } while ($uri)

        Write-Host "Captured $($policies.Count) active policy definition(s)." -ForegroundColor Green

        foreach ($p in $policies) {
            $safeName = ($p.displayName -replace '[^a-zA-Z0-9_\-]', '_')
            $filePath = Join-Path $targetDir "$safeName.json"
            $p | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8
        }

        # Save metadata manifest
        $manifest = @{
            Timestamp = $timestamp
            PolicyCount = $policies.Count
            Operator = (Get-MgContext).Account
            TenantId = (Get-MgContext).TenantId
        }
        $manifest | ConvertTo-Json | Out-File -FilePath (Join-Path $targetDir "manifest.json") -Encoding utf8

        Write-Host "Snapshot preserved at: $targetDir" -ForegroundColor Green
        return $timestamp
    } catch {
        Write-Error "Failed to generate pre-deployment snapshot: $($_.Exception.Message)"
        throw
    }
}

function List-Snapshots {
    $dirs = Get-ChildItem -Path $SnapshotsDir -Directory | Sort-Object CreationTime -Descending
    if ($dirs.Count -eq 0) {
        Write-Host "No policy snapshots found in $SnapshotsDir." -ForegroundColor Yellow
        return
    }

    Write-Host "`nAvailable Policy Rollback Snapshots:" -ForegroundColor Cyan
    foreach ($d in $dirs) {
        $manifestPath = Join-Path $d.FullName "manifest.json"
        if (Test-Path $manifestPath) {
            $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
            Write-Host "  Snapshot ID: $($d.Name) | Policies: $($m.PolicyCount) | Time (UTC): $($m.Timestamp) | Operator: $($m.Operator)" -ForegroundColor White
        } else {
            Write-Host "  Snapshot ID: $($d.Name) (No manifest)" -ForegroundColor Gray
        }
    }
}

function Restore-Snapshot ($targetSnapshotId) {
    if (-not $targetSnapshotId) {
        # Default to latest
        $latest = Get-ChildItem -Path $SnapshotsDir -Directory | Sort-Object CreationTime -Descending | Select-Object -First 1
        if (-not $latest) {
            throw "No snapshots available to restore."
        }
        $targetSnapshotId = $latest.Name
    }

    $sourceDir = Join-Path $SnapshotsDir $targetSnapshotId
    if (-not (Test-Path $sourceDir)) {
        throw "Snapshot '$targetSnapshotId' not found at $sourceDir"
    }

    Write-Host "`n[ROLLBACK INITIATED] Restoring Entra ID CA state from Snapshot: $targetSnapshotId..." -ForegroundColor Yellow
    $policyFiles = Get-ChildItem -Path $sourceDir -Filter "*.json" | Where-Object { $_.Name -ne "manifest.json" }

    foreach ($file in $policyFiles) {
        $policy = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        $policyId = $policy.id
        $displayName = $policy.displayName

        # Strip read-only properties before patching
        $body = $policy | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $body.PSObject.Properties.Remove("id")
        $body.PSObject.Properties.Remove("createdDateTime")
        $body.PSObject.Properties.Remove("modifiedDateTime")
        $jsonPayload = $body | ConvertTo-Json -Depth 10

        Write-Host "  Restoring '$displayName' (ID: $policyId)..." -ForegroundColor White
        try {
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$policyId"
            Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $jsonPayload -ContentType "application/json" | Out-Null
            Write-Host "  -> Successfully restored." -ForegroundColor Green
        } catch {
            Write-Error "  -> Failed to restore $displayName : $($_.Exception.Message)"
        }
    }
    Write-Host "`nRollback complete. Policies restored to state at $targetSnapshotId." -ForegroundColor Green
}

switch ($Action) {
    "Snapshot" { Save-TenantSnapshot }
    "List"     { List-Snapshots }
    "Restore"  { Restore-Snapshot $SnapshotId }
}
