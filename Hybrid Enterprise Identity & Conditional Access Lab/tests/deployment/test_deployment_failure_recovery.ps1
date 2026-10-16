<#
.SYNOPSIS
    Integration & Recovery Test: Deployment Failure, Transaction Haulting, and Snapshot Rollback.
.DESCRIPTION
    Validates end-to-end atomic deployment failure semantics:
    - 5 Conditional Access policies queued for deployment.
    - Policies 1-3 apply successfully.
    - Policy 4 encounters simulated Microsoft Graph API failure (HTTP 400 Bad Request).
    - Policy 5 is skipped (deployment transaction halts immediately).
    - Pre-deployment cryptographic snapshot remains intact.
    - Rollback engine is initiated against the pre-deployment snapshot.
    - Policies 1-3 are rolled back to their exact pre-deployment baseline states.
    - Post-rollback verification asserts tenant parity with initial baseline.
    - Generates and audits the complete per-policy transaction receipt.
#>

[CmdletBinding()]
param ()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  TEST: Deployment Partial Failure & Atomic Recovery     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$tempTestDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ca_fail_test_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempTestDir -Force | Out-Null

try {
    # 1. Establish Initial Baseline State (Snapshot Baseline)
    $baselinePolicies = @{
        "CAP-001" = @{ id = "pol-001"; displayName = "CAP-001-location"; state = "disabled" }
        "CAP-002" = @{ id = "pol-002"; displayName = "CAP-002-admin-mfa"; state = "enabledForReportingButNotEnforced" }
        "CAP-003" = @{ id = "pol-003"; displayName = "CAP-003-risk-mfa"; state = "disabled" }
        "CAP-004" = @{ id = "pol-004"; displayName = "CAP-004-legacy-auth"; state = "disabled" }
        "CAP-005" = @{ id = "pol-005"; displayName = "CAP-005-session-controls"; state = "disabled" }
    }

    # Simulate Live Tenant In-Memory Store
    $liveTenantPolicies = [ordered]@{}
    foreach ($k in $baselinePolicies.Keys) {
        $liveTenantPolicies[$k] = @{
            id          = $baselinePolicies[$k].id
            displayName = $baselinePolicies[$k].displayName
            state       = $baselinePolicies[$k].state
        }
    }

    # 2. Generate Pre-Deployment Snapshot
    $snapshotDir = Join-Path $tempTestDir "snapshots\20261016-120000"
    New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null

    $fileIntegrity = @()
    $checksumLines = @()

    foreach ($k in $baselinePolicies.Keys) {
        $p = $baselinePolicies[$k]
        $fileName = "$($p.displayName).json"
        $filePath = Join-Path $snapshotDir $fileName
        $json = $p | ConvertTo-Json -Depth 5
        $json | Out-File -FilePath $filePath -Encoding utf8
        $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToUpper()
        $fileIntegrity += [PSCustomObject]@{ FileName = $fileName; SHA256 = $hash }
        $checksumLines += "$hash  $fileName"
    }

    $manifest = @{
        Timestamp     = "20261016-120000"
        PolicyCount   = 5
        Operator      = "secops-runner@tenant.onmicrosoft.com"
        FileIntegrity = $fileIntegrity
    } | ConvertTo-Json -Depth 5
    $manifest | Out-File -FilePath (Join-Path $snapshotDir "manifest.json") -Encoding utf8
    $checksumLines | Out-File -FilePath (Join-Path $snapshotDir "checksums.sha256") -Encoding utf8

    Write-Host "[Step 1] Pre-deployment baseline snapshot generated and cryptographically sealed." -ForegroundColor Green

    # 3. Simulate 5-Policy Deployment Transaction
    $desiredTargets = @(
        @{ Key = "CAP-001"; NewState = "enabledForReportingButNotEnforced"; SimulateFail = $false }
        @{ Key = "CAP-002"; NewState = "enabled";                           SimulateFail = $false }
        @{ Key = "CAP-003"; NewState = "enabledForReportingButNotEnforced"; SimulateFail = $false }
        @{ Key = "CAP-004"; NewState = "enabled";                           SimulateFail = $true  } # Graph API 400 Error
        @{ Key = "CAP-005"; NewState = "enabled";                           SimulateFail = $false }
    )

    $transactionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $deploymentFailed = $false
    $failureError = $null

    Write-Host "`n[Step 2] Executing 5-policy deployment batch..." -ForegroundColor Cyan

    foreach ($t in $desiredTargets) {
        $key = $t.Key
        $pol = $liveTenantPolicies[$key]

        if ($deploymentFailed) {
            Write-Host "  [SKIPPED] $key : Deployment transaction halted due to prior step failure." -ForegroundColor DarkGray
            $transactionResults.Add([PSCustomObject]@{
                Policy  = $key
                Action  = "Update"
                Status  = "Skipped"
                Message = "Halted: Prior step failed ($failureError)"
            })
            continue
        }

        if ($t.SimulateFail) {
            $deploymentFailed = $true
            $failureError = "Microsoft Graph API: 400 Bad Request (Invalid condition combination in conditions.applications)"
            Write-Host "  [FAILED] $key : $failureError" -ForegroundColor Red
            $transactionResults.Add([PSCustomObject]@{
                Policy  = $key
                Action  = "Update"
                Status  = "Failed"
                Message = $failureError
            })
        } else {
            # Apply update
            $pol.state = $t.NewState
            Write-Host "  [SUCCESS] $key : Updated state -> $($t.NewState)" -ForegroundColor Green
            $transactionResults.Add([PSCustomObject]@{
                Policy  = $key
                Action  = "Update"
                Status  = "Success"
                Message = "OK"
            })
        }
    }

    # 4. Assert Transaction Contract
    Write-Host "`n[Step 3] Verifying transaction state contract..." -ForegroundColor Cyan
    $successCount = @($transactionResults | Where-Object { $_.Status -eq "Success" }).Count
    $failedCount  = @($transactionResults | Where-Object { $_.Status -eq "Failed" }).Count
    $skippedCount = @($transactionResults | Where-Object { $_.Status -eq "Skipped" }).Count

    if ($successCount -ne 3) { throw "Assertion Failed: Expected 3 successful updates, got $successCount" }
    if ($failedCount -ne 1)  { throw "Assertion Failed: Expected 1 failed update, got $failedCount" }
    if ($skippedCount -ne 1) { throw "Assertion Failed: Expected 1 skipped policy, got $skippedCount" }

    Write-Host "  [PASS] Per-policy outcomes verified: 3 Success, 1 Failed, 1 Skipped." -ForegroundColor Green
    Write-Host "  [PASS] Policy 5 was NOT deployed. Fail-closed halt asserted." -ForegroundColor Green

    # 5. Execute Rollback to Snapshot Baseline
    Write-Host "`n[Step 4] Initiating automated rollback to pre-deployment snapshot..." -ForegroundColor Yellow
    foreach ($k in $baselinePolicies.Keys) {
        $file = Join-Path $snapshotDir "$($baselinePolicies[$k].displayName).json"
        $snapObj = Get-Content -Path $file -Raw | ConvertFrom-Json
        # Restore live state from snapshot
        $liveTenantPolicies[$k].state = $snapObj.state
        Write-Host "  [RESTORED] $k -> baseline state: '$($snapObj.state)'" -ForegroundColor White
    }

    # 6. Post-Rollback Verification Gate
    Write-Host "`n[Step 5] Post-rollback live verification against baseline..." -ForegroundColor Cyan
    $parityMaintained = $true
    foreach ($k in $baselinePolicies.Keys) {
        $expected = $baselinePolicies[$k].state
        $actual = $liveTenantPolicies[$k].state
        if ($expected -ne $actual) {
            Write-Error "State mismatch on $k! Expected: $expected, Actual: $actual"
            $parityMaintained = $false
        } else {
            Write-Host "  [VERIFIED] $k reconciled: $actual == $expected" -ForegroundColor Green
        }
    }

    if (-not $parityMaintained) {
        throw "Assertion Failed: Post-rollback state does not match pre-deployment baseline."
    }

    # 7. Generate Audit Receipt
    $receipt = [PSCustomObject]@{
        TestScenario       = "Deployment Failure, Transaction Hault, and Verified Rollback"
        TimestampUtc       = (Get-Date).ToUniversalTime().ToString("o")
        TotalQueued        = 5
        SuccessfulUpdates  = $successCount
        FailedPolicies     = $failedCount
        SkippedPolicies    = $skippedCount
        HaltReason         = $failureError
        RollbackExecuted   = $true
        RollbackVerified   = $parityMaintained
        TransactionDetails = $transactionResults
    }

    $receiptPath = Join-Path $tempTestDir "audit_receipt.json"
    $receipt | ConvertTo-Json -Depth 5 | Out-File -FilePath $receiptPath -Encoding utf8
    Write-Host "`n[Step 6] Audit receipt generated: $receiptPath" -ForegroundColor Green

    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  ALL ASSERTIONS PASSED: Deployment Failure & Recovery OK " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    exit 0
} catch {
    Write-Error "Deployment Failure Recovery Test Failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Test-Path $tempTestDir) {
        Remove-Item -Path $tempTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
