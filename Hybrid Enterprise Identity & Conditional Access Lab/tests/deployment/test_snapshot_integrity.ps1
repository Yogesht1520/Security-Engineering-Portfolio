<#
.SYNOPSIS
    Comprehensive Unit & Security Test Suite: Snapshot Cryptographic Integrity & Tamper Resistance.
.DESCRIPTION
    Validates all security integrity gates in rollback_policies.ps1:
    - Test 1: Valid untampered snapshot passes verification.
    - Test 2: File content tampering is detected and rejected.
    - Test 3: Manifest tampering (modified hash or count) is detected and rejected.
    - Test 4: Checksum file tampering is detected and rejected.
    - Test 5: Unlisted extraneous file injection is detected and rejected.
    - Test 6: Missing policy file listed in manifest is detected and rejected.
    - Test 7: Duplicate policy IDs across snapshot files are detected and rejected.
    - Test 8: Malformed/corrupted JSON file is detected and rejected.
    - Test 9: Path traversal in snapshot filename (e.g., ../) is detected and rejected.
#>

[CmdletBinding()]
param ()

$rollbackScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\rollback_policies.ps1"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  TEST: Snapshot Cryptographic Integrity & Tamper Gates   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$tempSnapshotsDir = Join-Path ([System.IO.Path]::GetTempPath()) ("snap_test_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempSnapshotsDir -Force | Out-Null

function Initialize-SyntheticSnapshot {
    param (
        [string]$SubId,
        [hashtable[]]$Policies,
        [hashtable]$CustomManifest = $null,
        [string]$CustomChecksumContent = $null,
        [string[]]$ExtraFiles = @()
    )
    $sDir = Join-Path $tempSnapshotsDir $SubId
    New-Item -ItemType Directory -Path $sDir -Force | Out-Null

    $fileIntegrity = @()
    $checksumLines = @()

    foreach ($p in $Policies) {
        $fName = $p.FileName
        $fPath = Join-Path $sDir $fName
        if ($p.RawContent) {
            $p.RawContent | Out-File -FilePath $fPath -Encoding utf8
        } else {
            $p.Payload | ConvertTo-Json -Depth 5 | Out-File -FilePath $fPath -Encoding utf8
        }
        $hash = (Get-FileHash -Path $fPath -Algorithm SHA256).Hash.ToUpper()
        $fileIntegrity += [PSCustomObject]@{ FileName = $fName; SHA256 = $hash }
        $checksumLines += "$hash  $fName"
    }

    foreach ($extra in $ExtraFiles) {
        "EXTRA_UNLISTED_DATA" | Out-File -FilePath (Join-Path $sDir $extra) -Encoding utf8
    }

    if ($CustomChecksumContent) {
        $CustomChecksumContent | Out-File -FilePath (Join-Path $sDir "checksums.sha256") -Encoding utf8
    } else {
        $checksumLines | Out-File -FilePath (Join-Path $sDir "checksums.sha256") -Encoding utf8
    }

    if ($CustomManifest) {
        $CustomManifest | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $sDir "manifest.json") -Encoding utf8
    } else {
        $manifestObj = [PSCustomObject]@{
            Timestamp     = $SubId
            PolicyCount   = $Policies.Count
            Operator      = "test-runner"
            TenantId      = "test-tenant"
            FileIntegrity = $fileIntegrity
        }
        $manifestObj | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $sDir "manifest.json") -Encoding utf8
    }
    return $sDir
}

try {
    # -------------------------------------------------------------
    # Test 1: Valid Untampered Snapshot
    # -------------------------------------------------------------
    Write-Host "`n[Test 1] Verifying valid, untampered snapshot..." -ForegroundColor Yellow
    Initialize-SyntheticSnapshot -SubId "snap-01" -Policies @(
        @{ FileName = "CAP-001.json"; Payload = @{ id = "pol-1"; displayName = "CAP-001"; state = "disabled" } },
        @{ FileName = "CAP-002.json"; Payload = @{ id = "pol-2"; displayName = "CAP-002"; state = "enabled" } }
    ) | Out-Null

    $res1 = & $rollbackScript -Action Verify -SnapshotId "snap-01" -SnapshotsDir $tempSnapshotsDir
    if ($res1 -ne $true -and $res1 -notcontains $true) {
        throw "Test 1 Failed: Valid snapshot did not return true."
    }
    Write-Host "  [PASS] Test 1: Untampered snapshot verified successfully." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 2: Policy File Tampering
    # -------------------------------------------------------------
    Write-Host "`n[Test 2] Tampering with policy file content..." -ForegroundColor Yellow
    $dir2 = Initialize-SyntheticSnapshot -SubId "snap-02" -Policies @(
        @{ FileName = "CAP-001.json"; Payload = @{ id = "pol-1"; displayName = "CAP-001"; state = "disabled" } }
    )
    "TAMPERED_BYTE_DATA" | Out-File -FilePath (Join-Path $dir2 "CAP-001.json") -Encoding utf8

    $t2Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-02" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "SECURITY INTEGRITY FAILURE") { $t2Passed = $true }
    }
    if (-not $t2Passed) { throw "Test 2 Failed: File tampering was not caught with SECURITY INTEGRITY FAILURE." }
    Write-Host "  [PASS] Test 2: File content tampering caught and rejected." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 3: Manifest Tampering (Modified Hash)
    # -------------------------------------------------------------
    Write-Host "`n[Test 3] Tampering with manifest.json SHA-256 hash..." -ForegroundColor Yellow
    $dir3 = Initialize-SyntheticSnapshot -SubId "snap-03" -Policies @(
        @{ FileName = "CAP-001.json"; Payload = @{ id = "pol-1"; displayName = "CAP-001"; state = "disabled" } }
    )
    $man3Path = Join-Path $dir3 "manifest.json"
    $man3 = Get-Content $man3Path -Raw | ConvertFrom-Json
    $man3.FileIntegrity[0].SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
    $man3 | ConvertTo-Json -Depth 5 | Out-File -FilePath $man3Path -Encoding utf8

    $t3Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-03" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "SECURITY INTEGRITY FAILURE") { $t3Passed = $true }
    }
    if (-not $t3Passed) { throw "Test 3 Failed: Manifest tampering was not caught." }
    Write-Host "  [PASS] Test 3: Manifest hash tampering caught and rejected." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 4: Checksum File Tampering
    # -------------------------------------------------------------
    Write-Host "`n[Test 4] Tampering with checksums.sha256 file..." -ForegroundColor Yellow
    $dir4 = Initialize-SyntheticSnapshot -SubId "snap-04" -Policies @(
        @{ FileName = "CAP-001.json"; Payload = @{ id = "pol-1"; displayName = "CAP-001"; state = "disabled" } }
    )
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  CAP-001.json" | Out-File -FilePath (Join-Path $dir4 "checksums.sha256") -Encoding utf8

    $t4Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-04" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "SECURITY INTEGRITY FAILURE") { $t4Passed = $true }
    }
    if (-not $t4Passed) { throw "Test 4 Failed: Checksum file tampering was not caught." }
    Write-Host "  [PASS] Test 4: Checksum file tampering caught and rejected." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 5: Unlisted Extraneous File Injection
    # -------------------------------------------------------------
    Write-Host "`n[Test 5] Injecting unlisted extraneous file into snapshot..." -ForegroundColor Yellow
    [void](Initialize-SyntheticSnapshot -SubId "snap-05" -Policies @(
        @{ FileName = "CAP-001.json"; Payload = @{ id = "pol-1"; displayName = "CAP-001"; state = "disabled" } }
    ) -ExtraFiles @("unauthorized_injected_policy.json"))

    $t5Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-05" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "Unlisted extraneous file detected") { $t5Passed = $true }
    }
    if (-not $t5Passed) { throw "Test 5 Failed: Injected unlisted file was not caught." }
    Write-Host "  [PASS] Test 5: Unlisted extraneous file detected and rejected." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 6: Missing Policy File
    # -------------------------------------------------------------
    Write-Host "`n[Test 6] Testing missing policy file listed in manifest..." -ForegroundColor Yellow
    $dir6 = Initialize-SyntheticSnapshot -SubId "snap-06" -Policies @(
        @{ FileName = "CAP-001.json"; Payload = @{ id = "pol-1"; displayName = "CAP-001"; state = "disabled" } }
    )
    # Delete the policy file from disk
    Remove-Item -Path (Join-Path $dir6 "CAP-001.json") -Force

    $t6Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-06" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "missing from disk") { $t6Passed = $true }
    }
    if (-not $t6Passed) { throw "Test 6 Failed: Missing policy file was not caught." }
    Write-Host "  [PASS] Test 6: Missing policy file caught and rejected." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 7: Duplicate Policy ID Rejection
    # -------------------------------------------------------------
    Write-Host "`n[Test 7] Testing duplicate policy ID across snapshot files..." -ForegroundColor Yellow
    [void](Initialize-SyntheticSnapshot -SubId "snap-07" -Policies @(
        @{ FileName = "CAP-001.json"; Payload = @{ id = "DUPLICATE-ID"; displayName = "CAP-001"; state = "disabled" } },
        @{ FileName = "CAP-002.json"; Payload = @{ id = "DUPLICATE-ID"; displayName = "CAP-002"; state = "enabled" } }
    ))

    $t7Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-07" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "Duplicate policy ID detected") { $t7Passed = $true }
    }
    if (-not $t7Passed) { throw "Test 7 Failed: Duplicate policy ID was not caught." }
    Write-Host "  [PASS] Test 7: Duplicate policy ID caught and rejected." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 8: Malformed Corrupted JSON File
    # -------------------------------------------------------------
    Write-Host "`n[Test 8] Testing malformed/corrupted JSON file..." -ForegroundColor Yellow
    [void](Initialize-SyntheticSnapshot -SubId "snap-08" -Policies @(
        @{ FileName = "CAP-001.json"; RawContent = "{ invalid_json: missing_quotes " }
    ))

    $t8Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-08" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "malformed JSON") { $t8Passed = $true }
    }
    if (-not $t8Passed) { throw "Test 8 Failed: Malformed JSON was not caught." }
    Write-Host "  [PASS] Test 8: Malformed JSON file caught and rejected." -ForegroundColor Green

    # -------------------------------------------------------------
    # Test 9: Path Traversal Filename Attempt
    # -------------------------------------------------------------
    Write-Host "`n[Test 9] Testing path traversal filename rejection..." -ForegroundColor Yellow
    $dir9 = Join-Path $tempSnapshotsDir "snap-09"
    New-Item -ItemType Directory -Path $dir9 -Force | Out-Null
    "dummy" | Out-File -FilePath (Join-Path $dir9 "checksums.sha256") -Encoding utf8
    $travManifest = [PSCustomObject]@{
        Timestamp     = "snap-09"
        PolicyCount   = 1
        FileIntegrity = @(
            @{ FileName = "../../escape.json"; SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" }
        )
    }
    $travManifest | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $dir9 "manifest.json") -Encoding utf8

    $t9Passed = $false
    try {
        & $rollbackScript -Action Verify -SnapshotId "snap-09" -SnapshotsDir $tempSnapshotsDir 2>&1 | Out-Null
    } catch {
        if ($_.Exception.Message -match "Path traversal or illegal characters detected") { $t9Passed = $true }
    }
    if (-not $t9Passed) { throw "Test 9 Failed: Path traversal in filename was not caught." }
    Write-Host "  [PASS] Test 9: Path traversal in filename caught and rejected." -ForegroundColor Green

    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  ALL 9 SNAPSHOT INTEGRITY & TAMPER TESTS PASSED CLEANLY!  " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    exit 0
} catch {
    Write-Error "Snapshot Integrity Test Suite Failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Test-Path $tempSnapshotsDir) {
        Get-ChildItem -Path $tempSnapshotsDir -Recurse | ForEach-Object {
            Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $tempSnapshotsDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
