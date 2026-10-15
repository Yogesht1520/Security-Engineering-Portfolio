<#
.SYNOPSIS
    Automated Snapshot and Rollback Engine with Cryptographic Integrity Verification.
.DESCRIPTION
    Provides Zero Trust safety and recovery mechanisms for Conditional Access deployments:
    - Creates immutable pre-deployment snapshots of live Entra ID CA policies.
    - Implements atomic writes (.tmp staging -> atomic move) to prevent partial snapshot states.
    - Computes and records SHA-256 cryptographic hashes in both manifest.json and checksums.sha256.
    - Sets snapshot files to read-only for filesystem tamper-resistance.
    - Validates cryptographic SHA-256 integrity before initiating any restore/rollback operation.
    - Restores previous policy states in the event of an outage, unintended lockout, or regression.
.PARAMETER Action
    'Snapshot', 'Restore', 'Verify', or 'List'.
.PARAMETER SnapshotId
    Timestamp/ID of the snapshot to restore or verify (defaults to most recent).
.PARAMETER SnapshotsDir
    Directory where snapshots are preserved.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Snapshot", "Restore", "Verify", "List")]
    [string]$Action = "Snapshot",

    [string]$SnapshotId,

    [string]$SnapshotsDir = "$PSScriptRoot\..\..\snapshots"
)

if (-not (Test-Path $SnapshotsDir)) {
    New-Item -ItemType Directory -Path $SnapshotsDir -Force | Out-Null
}

function Test-SnapshotIntegrity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SnapshotDirectory
    )

    if (-not (Test-Path $SnapshotDirectory)) {
        throw "Snapshot directory not found: $SnapshotDirectory"
    }

    $manifestPath = Join-Path $SnapshotDirectory "manifest.json"
    $checksumPath = Join-Path $SnapshotDirectory "checksums.sha256"

    if (-not (Test-Path $manifestPath) -and -not (Test-Path $checksumPath)) {
        throw "[SECURITY INTEGRITY FAILURE] Snapshot lacks integrity metadata (manifest.json or checksums.sha256 missing)."
    }

    $expectedHashes = @{}

    if (Test-Path $checksumPath) {
        $lines = Get-Content -Path $checksumPath
        foreach ($line in $lines) {
            if ($line -match "^\s*([a-fA-F0-9]{64})\s+\*?(.+)\s*$") {
                $hash = $Matches[1].ToUpper()
                $fName = $Matches[2].Trim()
                $expectedHashes[$fName] = $hash
            }
        }
    } elseif (Test-Path $manifestPath) {
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.FileIntegrity) {
            foreach ($item in $manifest.FileIntegrity) {
                $expectedHashes[$item.FileName] = $item.SHA256.ToUpper()
            }
        }
    }

    if ($expectedHashes.Count -eq 0) {
        throw "[SECURITY INTEGRITY FAILURE] No file checksum entries found in snapshot integrity manifest."
    }

    Write-Host "Verifying cryptographic SHA-256 integrity for $($expectedHashes.Count) file(s)..." -ForegroundColor Cyan
    foreach ($entry in $expectedHashes.GetEnumerator()) {
        $fileName = $entry.Key
        $expectedHash = $entry.Value
        $targetFile = Join-Path $SnapshotDirectory $fileName

        if (-not (Test-Path $targetFile)) {
            throw "[SECURITY INTEGRITY FAILURE] Expected snapshot file missing from directory: '$fileName'."
        }

        $actualHash = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash.ToUpper()
        if ($actualHash -ne $expectedHash) {
            throw "[SECURITY INTEGRITY FAILURE] Cryptographic checksum mismatch for '$fileName'! Expected: $expectedHash, Actual: $actualHash. Snapshot tampering or corruption detected."
        }
        Write-Host "  [VERIFIED] $fileName (SHA-256: $actualHash)" -ForegroundColor Green
    }

    Write-Host "All snapshot files verified successfully against cryptographic manifest." -ForegroundColor Green
    return $true
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

        $fileIntegrityList = @()
        $checksumLines = @()

        foreach ($p in $policies) {
            $safeName = ($p.displayName -replace '[^a-zA-Z0-9_\-]', '_')
            $finalFileName = "$safeName.json"
            $finalFilePath = Join-Path $targetDir $finalFileName
            $tempFilePath  = Join-Path $targetDir "$safeName.tmp"

            # 1. Atomic write: write to .tmp staging file first
            $p | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempFilePath -Encoding utf8

            # 2. Calculate cryptographic SHA-256 checksum
            $sha256Hash = (Get-FileHash -Path $tempFilePath -Algorithm SHA256).Hash.ToUpper()

            # 3. Atomic move to target filename
            Move-Item -Path $tempFilePath -Destination $finalFilePath -Force

            # 4. Enforce filesystem read-only flag for tamper resistance
            Set-ItemProperty -Path $finalFilePath -Name IsReadOnly -Value $true

            $fileIntegrityList += [PSCustomObject]@{
                FileName = $finalFileName
                SHA256   = $sha256Hash
            }
            $checksumLines += "$sha256Hash  $finalFileName"
        }

        # 5. Write checksums.sha256 file
        $checksumPath = Join-Path $targetDir "checksums.sha256"
        $checksumLines | Out-File -FilePath $checksumPath -Encoding utf8
        Set-ItemProperty -Path $checksumPath -Name IsReadOnly -Value $true

        # 6. Save metadata manifest
        $manifestPath = Join-Path $targetDir "manifest.json"
        $manifest = [PSCustomObject]@{
            Timestamp     = $timestamp
            PolicyCount   = $policies.Count
            Operator      = (Get-MgContext).Account
            TenantId      = (Get-MgContext).TenantId
            FileIntegrity = $fileIntegrityList
        }
        $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding utf8
        Set-ItemProperty -Path $manifestPath -Name IsReadOnly -Value $true

        Write-Host "Snapshot cryptographically sealed and preserved at: $targetDir" -ForegroundColor Green
        return $timestamp
    } catch {
        Write-Error "Failed to generate pre-deployment snapshot: $($_.Exception.Message)"
        throw
    }
}

function Get-SnapshotList {
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

function Restore-Snapshot {
    [CmdletBinding()]
    param (
        [string]$TargetSnapshotId
    )

    if (-not $TargetSnapshotId) {
        $latest = Get-ChildItem -Path $SnapshotsDir -Directory | Sort-Object CreationTime -Descending | Select-Object -First 1
        if (-not $latest) {
            throw "No snapshots available to restore."
        }
        $TargetSnapshotId = $latest.Name
    }

    $sourceDir = Join-Path $SnapshotsDir $TargetSnapshotId
    if (-not (Test-Path $sourceDir)) {
        throw "Snapshot '$TargetSnapshotId' not found at $sourceDir"
    }

    # Mandatory Cryptographic Verification Gate
    Write-Host "`n[CRYPTOGRAPHIC VERIFICATION] Auditing snapshot integrity before restore..." -ForegroundColor Cyan
    Test-SnapshotIntegrity -SnapshotDirectory $sourceDir | Out-Null

    Write-Host "`n[ROLLBACK INITIATED] Restoring Entra ID CA state from Verified Snapshot: $TargetSnapshotId..." -ForegroundColor Yellow
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
    Write-Host "`nRollback complete. Policies restored to state at $TargetSnapshotId." -ForegroundColor Green
}

switch ($Action) {
    "Snapshot" { Save-TenantSnapshot }
    "Verify"   {
        $target = if ($SnapshotId) { Join-Path $SnapshotsDir $SnapshotId } else {
            (Get-ChildItem -Path $SnapshotsDir -Directory | Sort-Object CreationTime -Descending | Select-Object -First 1).FullName
        }
        Test-SnapshotIntegrity -SnapshotDirectory $target
    }
    "List"     { Get-SnapshotList }
    "Restore"  { Restore-Snapshot -TargetSnapshotId $SnapshotId }
}
