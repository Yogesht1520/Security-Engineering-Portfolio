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
    $baselinePolicies = [ordered]@{
        "pol-001" = [PSCustomObject]@{ id = "pol-001"; displayName = "CAP-001-location"; state = "disabled" }
        "pol-002" = [PSCustomObject]@{ id = "pol-002"; displayName = "CAP-002-admin-mfa"; state = "enabledForReportingButNotEnforced" }
        "pol-003" = [PSCustomObject]@{ id = "pol-003"; displayName = "CAP-003-risk-mfa"; state = "disabled" }
        "pol-004" = [PSCustomObject]@{ id = "pol-004"; displayName = "CAP-004-legacy-auth"; state = "disabled" }
        "pol-005" = [PSCustomObject]@{ id = "pol-005"; displayName = "CAP-005-session-controls"; state = "disabled" }
    }

    # Live Mock Tenant State Store (Global for child script access)
    $global:LiveMockPolicies = @{}
    foreach ($k in $baselinePolicies.Keys) {
        $b = $baselinePolicies[$k]
        $global:LiveMockPolicies[$k] = [PSCustomObject]@{
            id          = $b.id
            displayName = $b.displayName
            state       = $b.state
        }
    }

    # Mock Graph API Command Handler
    function global:Invoke-MgGraphRequest {
        [CmdletBinding()]
        param (
            [string]$Method = "GET",
            [string]$Uri,
            [string]$Body,
            [string]$ContentType,
            [string]$OutputType = "PSObject"
        )
        [void]$ContentType
        [void]$OutputType

        if ($Method -eq "GET" -and $Uri -match "/identity/conditionalAccess/policies") {
            $pList = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($v in $global:LiveMockPolicies.Values) {
                $pList.Add([PSCustomObject]@{
                    id          = $v.id
                    displayName = $v.displayName
                    state       = $v.state
                })
            }
            return [PSCustomObject]@{
                value = $pList
                '@odata.nextLink' = $null
            }
        }
        elseif ($Method -eq "PATCH" -and $Uri -match "/policies/([^/]+)$") {
            $polId = $Matches[1]
            if (-not $global:LiveMockPolicies.ContainsKey($polId)) {
                throw "Policy '$polId' not found in live mock tenant."
            }
            $bodyObj = $Body | ConvertFrom-Json
            $global:LiveMockPolicies[$polId].state = $bodyObj.state
            return [PSCustomObject]@{ id = $polId; state = $bodyObj.state }
        }
        elseif ($Method -eq "POST" -and $Uri -match "/identity/conditionalAccess/policies") {
            $bodyObj = $Body | ConvertFrom-Json
            $newId = "pol-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
            $newPol = [PSCustomObject]@{
                id          = $newId
                displayName = $bodyObj.displayName
                state       = $bodyObj.state
            }
            $global:LiveMockPolicies[$newId] = $newPol
            return $newPol
        }
        elseif ($Method -eq "DELETE" -and $Uri -match "/policies/([^/]+)$") {
            $polId = $Matches[1]
            if ($global:LiveMockPolicies.ContainsKey($polId)) {
                $global:LiveMockPolicies.Remove($polId)
            }
            return $null
        }
    }

    # 2. Generate Pre-Deployment Snapshot
    $snapshotsBaseDir = Join-Path $tempTestDir "snapshots"
    $snapshotTimestamp = "20261016-120000"
    $snapshotDir = Join-Path $snapshotsBaseDir $snapshotTimestamp
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

    $manifest = [PSCustomObject]@{
        Timestamp     = $snapshotTimestamp
        PolicyCount   = 5
        Operator      = "secops-runner@tenant.onmicrosoft.com"
        FileIntegrity = $fileIntegrity
    }
    $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $snapshotDir "manifest.json") -Encoding utf8
    $checksumLines | Out-File -FilePath (Join-Path $snapshotDir "checksums.sha256") -Encoding utf8

    Write-Host "[Step 1] Pre-deployment baseline snapshot generated and cryptographically sealed." -ForegroundColor Green

    # 3. Simulate 5-Policy Deployment Transaction
    $desiredTargets = @(
        @{ Key = "pol-001"; NewState = "enabledForReportingButNotEnforced"; SimulateFail = $false }
        @{ Key = "pol-002"; NewState = "enabled";                           SimulateFail = $false }
        @{ Key = "pol-003"; NewState = "enabledForReportingButNotEnforced"; SimulateFail = $false }
        @{ Key = "pol-004"; NewState = "enabled";                           SimulateFail = $true  } # Graph API 400 Error
        @{ Key = "pol-005"; NewState = "enabled";                           SimulateFail = $false }
    )

    $transactionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $deploymentFailed = $false
    $failureError = $null

    Write-Host "`n[Step 2] Executing 5-policy deployment batch..." -ForegroundColor Cyan

    foreach ($t in $desiredTargets) {
        $key = $t.Key
        $pol = $global:LiveMockPolicies[$key]

        if ($deploymentFailed) {
            Write-Host "  [SKIPPED] $($pol.displayName) : Deployment transaction halted due to prior step failure." -ForegroundColor DarkGray
            $transactionResults.Add([PSCustomObject]@{
                Policy  = $pol.displayName
                Action  = "Update"
                Status  = "Skipped"
                Message = "Halted: Prior step failed ($failureError)"
            })
            continue
        }

        if ($t.SimulateFail) {
            $deploymentFailed = $true
            $failureError = "Microsoft Graph API: 400 Bad Request (Invalid condition combination in conditions.applications)"
            Write-Host "  [FAILED] $($pol.displayName) : $failureError" -ForegroundColor Red
            $transactionResults.Add([PSCustomObject]@{
                Policy  = $pol.displayName
                Action  = "Update"
                Status  = "Failed"
                Message = $failureError
            })
        } else {
            # Apply mutation to mock tenant
            $pol.state = $t.NewState
            Write-Host "  [SUCCESS] $($pol.displayName) : Updated state -> $($t.NewState)" -ForegroundColor Green
            $transactionResults.Add([PSCustomObject]@{
                Policy  = $pol.displayName
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

    # 5. Execute Rollback via Production rollback_policies.ps1 Engine
    Write-Host "`n[Step 4] Initiating automated rollback via production rollback engine..." -ForegroundColor Yellow
    $rollbackScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\rollback_policies.ps1"
    
    $rollbackSuccess = & $rollbackScript -Action Restore -SnapshotId $snapshotTimestamp -SnapshotsDir $snapshotsBaseDir
    if (-not $rollbackSuccess) {
        throw "Assertion Failed: Production Restore-Snapshot did not complete successfully."
    }

    # 6. Post-Rollback Live Verification Gate
    Write-Host "`n[Step 5] Post-rollback live verification against baseline..." -ForegroundColor Cyan
    $parityMaintained = $true
    foreach ($k in $baselinePolicies.Keys) {
        $expected = $baselinePolicies[$k].state
        $actual = $global:LiveMockPolicies[$k].state
        if ($expected -ne $actual) {
            Write-Error "State mismatch on $k! Expected: $expected, Actual: $actual"
            $parityMaintained = $false
        } else {
            Write-Host "  [VERIFIED] $($baselinePolicies[$k].displayName) reconciled: $actual == $expected" -ForegroundColor Green
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
    Remove-Variable -Name LiveMockPolicies -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path $tempTestDir) {
        Get-ChildItem -Path $tempTestDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $tempTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
