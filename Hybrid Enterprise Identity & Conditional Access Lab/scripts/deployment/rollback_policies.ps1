<#
.SYNOPSIS
    Automated Snapshot and Rollback Engine with Cryptographic Integrity Verification.
.DESCRIPTION
    Provides Zero Trust safety and recovery mechanisms for Conditional Access deployments:
    - Creates pre-deployment SHA-256 integrity-checked snapshots of live Entra ID CA policies.
    - Implements atomic writes (.tmp staging -> atomic move) to prevent partial snapshot states.
    - Computes and records SHA-256 cryptographic hashes in both manifest.json and checksums.sha256.
    - Cross-checks manifest.json against checksums.sha256 and treats manifest as authoritative whitelist.
    - Rejects unlisted files, duplicate policy IDs, corrupted JSON, and path traversal attempts.
    - Resolves policies by immutable ID first, falling back to unique display name candidates.
    - Deletes only session-created policies during rollback, leaving existing tenant policies intact.
    - Restores previous policy states and executes deep canonical parity verification against Microsoft Graph.
    - Note on snapshot authenticity: Local SHA-256 checksums provide tamper-evident integrity checking
      against accidental corruption and local drift. Production implementations should complement local
      integrity checks with signed manifests, isolated signing keys, restricted ACLs, and remote versioned storage.
.PARAMETER Action
    'Snapshot', 'Restore', 'Verify', or 'List'.
.PARAMETER SnapshotId
    Timestamp/ID of the snapshot to restore or verify (defaults to most recent).
.PARAMETER SnapshotsDir
    Directory where snapshots are preserved.
.PARAMETER SessionCreatedPolicyIds
    Optional array of policy IDs created during the failed deployment transaction to be deleted during rollback.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Snapshot", "Restore", "Verify", "List")]
    [string]$Action = "Snapshot",

    [string]$SnapshotId,

    [string]$SnapshotsDir = "$PSScriptRoot\..\..\snapshots",

    [string[]]$SessionCreatedPolicyIds = @()
)

. "$PSScriptRoot\deployment_engine.ps1"

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
        throw "[SECURITY INTEGRITY FAILURE] Snapshot directory not found: $SnapshotDirectory"
    }

    $manifestPath = Join-Path $SnapshotDirectory "manifest.json"
    $checksumPath = Join-Path $SnapshotDirectory "checksums.sha256"

    # 1. Require BOTH manifest.json and checksums.sha256
    if (-not (Test-Path $manifestPath) -or -not (Test-Path $checksumPath)) {
        throw "[SECURITY INTEGRITY FAILURE] Snapshot lacks required integrity metadata (manifest.json or checksums.sha256 missing)."
    }

    # 2. Parse manifest.json
    try {
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
    } catch {
        throw "[SECURITY INTEGRITY FAILURE] manifest.json is corrupted or not valid JSON: $($_.Exception.Message)"
    }

    if (-not $manifest.FileIntegrity -or $manifest.FileIntegrity.Count -eq 0) {
        throw "[SECURITY INTEGRITY FAILURE] manifest.json contains zero registered policy file entries."
    }

    # 3. Build Manifest Authoritative Whitelist
    $manifestHashes = @{}
    $allowedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $allowedFiles.Add("manifest.json") | Out-Null
    $allowedFiles.Add("checksums.sha256") | Out-Null

    foreach ($item in $manifest.FileIntegrity) {
        $fName = $item.FileName
        # Filename sanitization against path traversal
        if ($fName -notmatch '^[A-Za-z0-9_\-]+\.json$') {
            throw "[SECURITY INTEGRITY FAILURE] Path traversal or illegal characters detected in snapshot filename: '$fName'."
        }
        $manifestHashes[$fName] = $item.SHA256.ToUpper()
        $allowedFiles.Add($fName) | Out-Null
    }

    # 4. Reject unlisted files in snapshot directory (Tamper Detection)
    $actualFilesOnDisk = Get-ChildItem -Path $SnapshotDirectory -File
    foreach ($fileOnDisk in $actualFilesOnDisk) {
        if (-not $allowedFiles.Contains($fileOnDisk.Name)) {
            throw "[SECURITY INTEGRITY FAILURE] Unlisted extraneous file detected in snapshot directory: '$($fileOnDisk.Name)'. Snapshot tampering or unapproved file injection detected."
        }
    }

    # 5. Parse and Cross-Check checksums.sha256 against manifest
    $checksumHashes = @{}
    $checksumLines = Get-Content -Path $checksumPath
    foreach ($line in $checksumLines) {
        if ($line -match "^\s*([a-fA-F0-9]{64})\s+\*?(.+)\s*$") {
            $h = $Matches[1].ToUpper()
            $fn = $Matches[2].Trim()
            $checksumHashes[$fn] = $h
        }
    }

    if ($checksumHashes.Count -ne $manifestHashes.Count) {
        throw "[SECURITY INTEGRITY FAILURE] Entry count mismatch between manifest.json ($($manifestHashes.Count)) and checksums.sha256 ($($checksumHashes.Count))."
    }

    foreach ($entry in $manifestHashes.GetEnumerator()) {
        $fn = $entry.Key
        if (-not $checksumHashes.ContainsKey($fn)) {
            throw "[SECURITY INTEGRITY FAILURE] File '$fn' listed in manifest.json is missing from checksums.sha256."
        }
        if ($checksumHashes[$fn] -ne $entry.Value) {
            throw "[SECURITY INTEGRITY FAILURE] Cryptographic hash conflict between manifest.json and checksums.sha256 for '$fn'!"
        }
    }

    # 6. Verify Filesystem Integrity and Content Validity
    Write-Host "Verifying cryptographic SHA-256 integrity for $($manifestHashes.Count) file(s)..." -ForegroundColor Cyan
    $seenPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in $manifestHashes.GetEnumerator()) {
        $fileName = $entry.Key
        $expectedHash = $entry.Value
        $targetFile = Join-Path $SnapshotDirectory $fileName

        if (-not (Test-Path $targetFile)) {
            throw "[SECURITY INTEGRITY FAILURE] Expected snapshot file missing from disk: '$fileName'."
        }

        $actualHash = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash.ToUpper()
        if ($actualHash -ne $expectedHash) {
            throw "[SECURITY INTEGRITY FAILURE] Cryptographic checksum mismatch for '$fileName'! Expected: $expectedHash, Actual: $actualHash. Snapshot file tampered or corrupted."
        }

        # Validate JSON content integrity
        try {
            $parsedJson = Get-Content -Path $targetFile -Raw | ConvertFrom-Json
        } catch {
            throw "[SECURITY INTEGRITY FAILURE] Snapshot policy file '$fileName' contains malformed JSON."
        }

        if (-not $parsedJson.id -or -not $parsedJson.displayName) {
            throw "[SECURITY INTEGRITY FAILURE] Snapshot policy file '$fileName' missing mandatory 'id' or 'displayName'."
        }

        if ($seenPolicyIds.Contains($parsedJson.id)) {
            throw "[SECURITY INTEGRITY FAILURE] Duplicate policy ID detected in snapshot: '$($parsedJson.id)' in file '$fileName'."
        }
        $seenPolicyIds.Add($parsedJson.id) | Out-Null

        Write-Host "  [VERIFIED] $fileName (SHA-256: $actualHash, Policy ID: $($parsedJson.id))" -ForegroundColor Green
    }

    Write-Host "All snapshot files verified successfully against authoritative manifest and checksums." -ForegroundColor Green
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
        $operator = try { (Get-MgContext).Account } catch { "secops-operator" }
        $tenantId = try { (Get-MgContext).TenantId } catch { "unknown" }
        $manifest = [PSCustomObject]@{
            Timestamp     = $timestamp
            PolicyCount   = $policies.Count
            Operator      = $operator
            TenantId      = $tenantId
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
        [string]$TargetSnapshotId,
        [string[]]$CreatedPolicyIds = @()
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
    $manifestPath = Join-Path $sourceDir "manifest.json"
    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json

    $snapshotPolicies = @()
    foreach ($item in $manifest.FileIntegrity) {
        $filePath = Join-Path $sourceDir $item.FileName
        $snapshotPolicies += Get-Content -Path $filePath -Raw | ConvertFrom-Json
    }

    # Query current live policies
    Write-Host "Querying current live tenant policies..." -ForegroundColor Cyan
    $livePolicies = @()
    $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        if ($response.value) { $livePolicies += $response.value }
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    # 1. Scoped Deletion: Delete policies created during the current transaction
    if ($CreatedPolicyIds -and $CreatedPolicyIds.Count -gt 0) {
        Write-Host "`n[TRANSACTION CLEANUP] Deleting $($CreatedPolicyIds.Count) policy(ies) created during the failed transaction..." -ForegroundColor Yellow
        foreach ($cId in $CreatedPolicyIds) {
            $matchLive = $livePolicies | Where-Object { $_.id -eq $cId } | Select-Object -First 1
            $nameStr = if ($matchLive) { $matchLive.displayName } else { $cId }
            Write-Host "  [Deleting] $nameStr (ID: $cId)..." -ForegroundColor DarkYellow
            try {
                $delUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$cId"
                Invoke-MgGraphRequest -Method DELETE -Uri $delUri -ErrorAction Stop
                Write-Host "  -> Successfully deleted session-created policy." -ForegroundColor Green
            } catch {
                Write-Error "  -> Failed to delete session-created policy '$nameStr': $($_.Exception.Message)"
                throw
            }
        }
    }

    # 2. Restore/Reconcile all snapshot policies
    Write-Host "`nRestoring snapshot policy states..." -ForegroundColor Cyan
    foreach ($policy in $snapshotPolicies) {
        $policyId = $policy.id
        $displayName = $policy.displayName

        # Strip read-only properties before payload submission
        $body = $policy | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $body.PSObject.Properties.Remove("id")
        $body.PSObject.Properties.Remove("createdDateTime")
        $body.PSObject.Properties.Remove("modifiedDateTime")
        $jsonPayload = $body | ConvertTo-Json -Depth 10

        # Finding 3: Immutable policy ID as primary identity; fallback to unique display name candidate
        $existingLive = $null
        if ($policyId) {
            $matchById = @($livePolicies | Where-Object { $_.id -eq $policyId })
            if ($matchById.Count -eq 1) {
                $existingLive = $matchById[0]
            } elseif ($matchById.Count -gt 1) {
                throw "[ROLLBACK AMBIGUITY] Critical directory error: Multiple live policies found with identical ID '$policyId'."
            }
        }

        # If policy ID is missing from live tenant (e.g. deleted or re-created with new ID), check for exactly 1 replacement candidate by display name
        if (-not $existingLive) {
            $matchByName = @($livePolicies | Where-Object { $_.displayName -eq $displayName })
            if ($matchByName.Count -gt 1) {
                throw "[ROLLBACK AMBIGUITY] Multiple policies ($($matchByName.Count)) match target display name '$displayName' in live tenant. Rollback halted to prevent cross-policy corruption."
            } elseif ($matchByName.Count -eq 1) {
                $existingLive = $matchByName[0]
                Write-Warning "  [POLICY ID RE-MAPPING] Policy ID '$policyId' was not found; safely resolved to single permitted replacement candidate ID '$($existingLive.id)' by display name '$displayName'."
            }
        }

        if ($existingLive) {
            # Finding 2: Canonical Policy Normalization & Parity Comparison
            $diffs = Compare-CanonicalPolicyParity -LivePolicy $existingLive -SnapshotPolicy $policy
            if ($diffs.Count -eq 0) {
                Write-Host "  [In Parity] '$displayName' (ID: $($existingLive.id)) matches snapshot baseline. No patch required." -ForegroundColor Gray
                continue
            }

            Write-Host "  [Restoring Existing] '$displayName' (ID: $($existingLive.id))..." -ForegroundColor White
            try {
                $patchUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existingLive.id)"
                Invoke-MgGraphRequest -Method PATCH -Uri $patchUri -Body $jsonPayload -ContentType "application/json" -ErrorAction Stop | Out-Null
                Write-Host "  -> Successfully restored." -ForegroundColor Green
            } catch {
                Write-Error "  -> Failed to restore $displayName : $($_.Exception.Message)"
                throw
            }
        } else {
            Write-Host "  [Re-creating Missing] '$displayName'..." -ForegroundColor Cyan
            try {
                $postUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                Invoke-MgGraphRequest -Method POST -Uri $postUri -Body $jsonPayload -ContentType "application/json" -ErrorAction Stop | Out-Null
                Write-Host "  -> Successfully re-created." -ForegroundColor Green
            } catch {
                Write-Error "  -> Failed to re-create $displayName : $($_.Exception.Message)"
                throw
            }
        }
    }

    # 3. Post-Rollback Live Graph Verification Gate (Full Canonical Parity)
    Write-Host "`n[POST-ROLLBACK VERIFICATION] Querying Graph to verify live tenant state against snapshot..." -ForegroundColor Cyan
    $verifyPolicies = @()
    $verifyUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $verifyUri -OutputType PSObject
        if ($resp.value) { $verifyPolicies += $resp.value }
        $verifyUri = $resp.'@odata.nextLink'
    } while ($verifyUri)

    $allVerified = $true
    foreach ($sp in $snapshotPolicies) {
        $matching = @($verifyPolicies | Where-Object { ($sp.id -and $_.id -eq $sp.id) -or ($_.displayName -eq $sp.displayName) })
        if ($matching.Count -eq 0) {
            Write-Error "  [VERIFY FAIL] Restored policy '$($sp.displayName)' not found in live tenant!"
            $allVerified = $false
            continue
        }
        if ($matching.Count -gt 1) {
            Write-Error "  [VERIFY FAIL] Ambiguous duplicate policy detected! $($matching.Count) policies share display name '$($sp.displayName)'."
            $allVerified = $false
            continue
        }

        $livePolicy = $matching[0]
        $mismatches = Compare-CanonicalPolicyParity -LivePolicy $livePolicy -SnapshotPolicy $sp

        if ($mismatches.Count -gt 0) {
            Write-Warning "  [VERIFY CONFIG DRIFT] Policy '$($sp.displayName)' configuration mismatch between snapshot and live tenant ($($mismatches.Count) field(s) drifted):"
            foreach ($m in $mismatches) {
                Write-Warning "    * $m"
            }
            $allVerified = $false
        } else {
            Write-Host "  [VERIFY PASS] '$($sp.displayName)' full canonical configuration verified in 100% parity with snapshot." -ForegroundColor Green
        }
    }

    # Assert zero session-created policies remain
    if ($CreatedPolicyIds -and $CreatedPolicyIds.Count -gt 0) {
        foreach ($cId in $CreatedPolicyIds) {
            $orphanLeft = $verifyPolicies | Where-Object { $_.id -eq $cId }
            if ($orphanLeft) {
                Write-Error "  [VERIFY FAIL] Session-created policy '$cId' still exists in live tenant after rollback!"
                $allVerified = $false
            }
        }
    }

    if ($allVerified) {
        Write-Host "`n[ROLLBACK SUCCESS] All $($snapshotPolicies.Count) policy(ies) cryptographically and operationally reconciled with snapshot $TargetSnapshotId." -ForegroundColor Green
        return $true
    } else {
        throw "[ROLLBACK VERIFICATION FAILURE] Live tenant state does not match snapshot baseline after restore operation."
    }
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
    "Restore"  { Restore-Snapshot -TargetSnapshotId $SnapshotId -CreatedPolicyIds $SessionCreatedPolicyIds }
}
