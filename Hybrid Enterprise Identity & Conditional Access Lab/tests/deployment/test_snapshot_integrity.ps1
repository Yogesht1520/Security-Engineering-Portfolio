# Unit Test: Cryptographic Snapshot Integrity & Tamper Resistance
$rollbackScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\rollback_policies.ps1"

Write-Host "Running Snapshot Cryptographic Integrity Unit Tests..." -ForegroundColor Cyan

$tempSnapshotsDir = Join-Path ([System.IO.Path]::GetTempPath()) ("snap_test_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempSnapshotsDir -Force | Out-Null

try {
    # 1. Setup synthetic snapshot
    $snapshotId = "20261015-120000"
    $snapshotDir = Join-Path $tempSnapshotsDir $snapshotId
    New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null

    $samplePolicy = @{
        id = "test-policy-1234"
        displayName = "CAP-001: Block Sign-in Outside Allowed Regions"
        state = "enabledForReportingButNotEnforced"
    } | ConvertTo-Json

    $policyFileName = "CAP-001.json"
    $policyPath = Join-Path $snapshotDir $policyFileName
    $samplePolicy | Out-File -FilePath $policyPath -Encoding utf8

    $sha256 = (Get-FileHash -Path $policyPath -Algorithm SHA256).Hash.ToUpper()

    # Create checksums.sha256
    "$sha256  $policyFileName" | Out-File -FilePath (Join-Path $snapshotDir "checksums.sha256") -Encoding utf8

    # Create manifest.json
    $manifest = @{
        Timestamp = $snapshotId
        PolicyCount = 1
        FileIntegrity = @(
            @{ FileName = $policyFileName; SHA256 = $sha256 }
        )
    } | ConvertTo-Json
    $manifest | Out-File -FilePath (Join-Path $snapshotDir "manifest.json") -Encoding utf8

    # Test 1: Verify valid snapshot
    Write-Host "`n[Test 1] Verifying untampered snapshot..." -ForegroundColor Yellow
    $verifyResult = & $rollbackScript -Action Verify -SnapshotId $snapshotId -SnapshotsDir $tempSnapshotsDir
    if ($verifyResult -ne $true -and $verifyResult -notcontains $true) {
        Write-Error "Test 1 Failed: Valid snapshot did not return true."
        exit 1
    }
    Write-Host "  [PASS] Test 1: Valid snapshot successfully verified with matching SHA-256." -ForegroundColor Green

    # Test 2: Tamper with snapshot file and verify failure
    Write-Host "`n[Test 2] Tampering with snapshot file to simulate unauthorized modification..." -ForegroundColor Yellow
    # Remove read-only attribute if set, then modify content
    Set-ItemProperty -Path $policyPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    "TAMPERED_CONTENT" | Out-File -FilePath $policyPath -Encoding utf8

    $tamperDetected = $false
    try {
        $tamperOutput = & $rollbackScript -Action Verify -SnapshotId $snapshotId -SnapshotsDir $tempSnapshotsDir 2>&1
        if (($tamperOutput | Out-String) -match "SECURITY INTEGRITY FAILURE") {
            $tamperDetected = $true
            Write-Host "  [PASS] Test 2: Tampered snapshot correctly rejected with SECURITY INTEGRITY FAILURE." -ForegroundColor Green
        }
    } catch {
        $tamperDetected = $true
        Write-Host "  [PASS] Test 2: Tampered snapshot correctly rejected with exception." -ForegroundColor Green
    }

    if (-not $tamperDetected) {
        Write-Error "Test 2 Failed: Tampered snapshot was NOT rejected!"
        exit 1
    }

} finally {
    # Cleanup temp directory
    Get-ChildItem -Path $tempSnapshotsDir -Recurse | ForEach-Object {
        Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    }
    Remove-Item -Path $tempSnapshotsDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`nAll snapshot cryptographic integrity tests PASSED!" -ForegroundColor Green
$global:LASTEXITCODE = 0
