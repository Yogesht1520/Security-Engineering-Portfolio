<#
.SYNOPSIS
    Integration & Recovery Test: Deployment Failure, Transaction Halting, Ambiguous Write Recovery, and Snapshot Rollback.
.DESCRIPTION
    Validates end-to-end atomic deployment failure semantics invoking the production orchestrator:
    - Scenario 1: Partial Failure & Automatic Rollback via Invoke-PolicyDeploymentTransaction
      * 5 Conditional Access policies queued for deployment.
      * Policies 1-3 apply successfully.
      * Policy 4 encounters simulated Microsoft Graph API failure (HTTP 400 Bad Request).
      * Policy 5 is skipped (deployment transaction halts immediately).
      * Production Invoke-PolicyDeploymentTransaction automatically triggers rollback_policies.ps1.
      * Policies 1-3 are rolled back to their exact pre-deployment baseline states.
      * Post-rollback verification asserts tenant parity with initial baseline.
    - Scenario 2: Ambiguous Graph Write Recovery (Simulated Network Timeout / Lost Response)
      * Policy write succeeds on Graph server, but client connection drops before response is received.
      * Production orchestrator detects ambiguous state by re-querying Graph and comparing to snapshot.
      * Treats mutation as applied and triggers automatic rollback to restore baseline.
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

    # Live Mock Tenant State Store
    $global:LiveMockPolicies = @{}
    foreach ($k in $baselinePolicies.Keys) {
        $b = $baselinePolicies[$k]
        $global:LiveMockPolicies[$k] = [PSCustomObject]@{
            id          = $b.id
            displayName = $b.displayName
            state       = $b.state
        }
    }

    # Simulation control flags
    $global:SimulateTimeoutOnPolId = $null
    $global:SimulateErrorOnPolId = $null

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

        # 1. GET specific policy by ID
        if ($Method -eq "GET" -and $Uri -match "/identity/conditionalAccess/policies/([^/?]+)$") {
            $polId = $Matches[1]
            if ($global:LiveMockPolicies.ContainsKey($polId)) {
                $p = $global:LiveMockPolicies[$polId]
                return [PSCustomObject]@{
                    id          = $p.id
                    displayName = $p.displayName
                    state       = $p.state
                }
            } else {
                throw "Policy '$polId' not found."
            }
        }

        # 2. GET policies collection
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

        # 3. PATCH policy
        if ($Method -eq "PATCH" -and $Uri -match "/policies/([^/?]+)$") {
            $polId = $Matches[1]
            if (-not $global:LiveMockPolicies.ContainsKey($polId)) {
                throw "Policy '$polId' not found in live mock tenant."
            }
            $bodyObj = $Body | ConvertFrom-Json

            # Check simulated network timeout after write
            if ($global:SimulateTimeoutOnPolId -eq $polId) {
                $global:SimulateTimeoutOnPolId = $null
                # Server committed the change, but response was lost in transit
                $global:LiveMockPolicies[$polId].state = $bodyObj.state
                throw [System.Net.WebException]::new("The operation has timed out: Connection dropped after server processed request.")
            }

            # Check simulated API error
            if ($global:SimulateErrorOnPolId -eq $polId) {
                throw "Microsoft Graph API: 400 Bad Request (Invalid condition combination in conditions.applications)"
            }

            $global:LiveMockPolicies[$polId].state = $bodyObj.state
            return [PSCustomObject]@{ id = $polId; state = $bodyObj.state }
        }

        # 4. POST policy
        if ($Method -eq "POST" -and $Uri -match "/identity/conditionalAccess/policies") {
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

        # 5. DELETE policy
        if ($Method -eq "DELETE" -and $Uri -match "/policies/([^/?]+)$") {
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

    Write-Host "[Step 1] Pre-deployment baseline snapshot generated with SHA-256 integrity verification." -ForegroundColor Green

    # 3. Load Production Deployment Orchestrator
    $deployScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\deploy_ca_policies.ps1"
    . $deployScript -OnlyExportFunctions
    $rollbackScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\rollback_policies.ps1"
    $reportsDir = Join-Path $tempTestDir "reports"

    # =========================================================================
    # SCENARIO 1: Partial Failure & Automatic Rollback via Production Orchestrator
    # =========================================================================
    Write-Host "`n[Scenario 1] Executing 5-policy deployment batch via production Invoke-PolicyDeploymentTransaction..." -ForegroundColor Cyan

    $global:SimulateErrorOnPolId = "pol-004"
    $global:SimulateTimeoutOnPolId = $null

    $actionsToTake = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location";        PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location";        state = "enabledForReportingButNotEnforced" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-002-admin-mfa";       PolicyId = "pol-002"; Payload = @{ displayName = "CAP-002-admin-mfa";       state = "enabled" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-003-risk-mfa";        PolicyId = "pol-003"; Payload = @{ displayName = "CAP-003-risk-mfa";        state = "enabledForReportingButNotEnforced" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-004-legacy-auth";     PolicyId = "pol-004"; Payload = @{ displayName = "CAP-004-legacy-auth";     state = "enabled" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-005-session-controls";PolicyId = "pol-005"; Payload = @{ displayName = "CAP-005-session-controls";state = "enabled" } }
    )

    $result1 = Invoke-PolicyDeploymentTransaction `
        -ActionsToTake $actionsToTake `
        -SnapshotId $snapshotTimestamp `
        -RollbackScript $rollbackScript `
        -ReceiptsDirectory $reportsDir `
        -SnapshotsDir $snapshotsBaseDir

    # Assertions for Scenario 1
    Write-Host "`n[Scenario 1 Assertions] Verifying transaction state contract..." -ForegroundColor Cyan
    if ($result1.TransactionState -ne "FailedAndRolledBack") {
        throw "Assertion Failed: Expected TransactionState 'FailedAndRolledBack', got '$($result1.TransactionState)'"
    }

    $receipt1 = $result1.Receipt
    if ($receipt1.RollbackExecuted -ne $true) { throw "Assertion Failed: Rollback was not executed by orchestrator." }
    if ($receipt1.RollbackVerified -ne $true) { throw "Assertion Failed: Rollback was not verified by orchestrator." }

    $txDetails = $receipt1.PolicyTransactions
    $sCount = @($txDetails | Where-Object { $_.Status -eq "Success" }).Count
    $fCount = @($txDetails | Where-Object { $_.Status -eq "Failed" }).Count
    $kCount = @($txDetails | Where-Object { $_.Status -eq "Skipped" }).Count

    if ($sCount -ne 3) { throw "Assertion Failed: Expected 3 successful updates before failure, got $sCount" }
    if ($fCount -ne 1) { throw "Assertion Failed: Expected 1 failed update, got $fCount" }
    if ($kCount -ne 1) { throw "Assertion Failed: Expected 1 skipped policy, got $kCount" }

    # Verify live mock policies match baseline after automatic rollback
    foreach ($k in $baselinePolicies.Keys) {
        $expected = $baselinePolicies[$k].state
        $actual = $global:LiveMockPolicies[$k].state
        if ($expected -ne $actual) {
            throw "Assertion Failed: State mismatch on $k! Expected: $expected, Actual: $actual"
        }
    }
    Write-Host "  [PASS] Scenario 1: Production orchestrator halted on failure and automatically restored baseline parity." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 2: Ambiguous Graph Write Recovery (Timeout after Server Applied Write)
    # =========================================================================
    Write-Host "`n[Scenario 2] Testing ambiguous write recovery (network timeout after server applied change)..." -ForegroundColor Cyan

    $global:SimulateErrorOnPolId = $null
    $global:SimulateTimeoutOnPolId = "pol-001"

    $actionsToTake2 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
    )

    $result2 = Invoke-PolicyDeploymentTransaction `
        -ActionsToTake $actionsToTake2 `
        -SnapshotId $snapshotTimestamp `
        -RollbackScript $rollbackScript `
        -ReceiptsDirectory $reportsDir `
        -SnapshotsDir $snapshotsBaseDir

    # Assertions for Scenario 2
    Write-Host "`n[Scenario 2 Assertions] Verifying ambiguous write detection and recovery..." -ForegroundColor Cyan
    if ($result2.TransactionState -ne "FailedAndRolledBack") {
        throw "Assertion Failed: Expected TransactionState 'FailedAndRolledBack' under ambiguous write, got '$($result2.TransactionState)'"
    }

    $receipt2 = $result2.Receipt
    if ($receipt2.MutationsApplied -lt 1) {
        throw "Assertion Failed: Ambiguous write was not detected as applied (MutationsApplied should be >= 1, got $($receipt2.MutationsApplied))"
    }
    if ($receipt2.RollbackExecuted -ne $true) {
        throw "Assertion Failed: Rollback was not triggered for ambiguous write!"
    }

    # Verify live mock policies restored to pre-deployment baseline
    if ($global:LiveMockPolicies["pol-001"].state -ne "disabled") {
        throw "Assertion Failed: Policy pol-001 state after ambiguous write rollback should be 'disabled', got '$($global:LiveMockPolicies['pol-001'].state)'"
    }
    Write-Host "  [PASS] Scenario 2: Ambiguous write detected by orchestrator, flagged as applied, and cleanly rolled back." -ForegroundColor Green

    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  ALL ASSERTIONS PASSED: Orchestrator Failure & Recovery OK" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    exit 0
} catch {
    Write-Error "Deployment Failure Recovery Test Failed: $($_.Exception.Message)"
    exit 1
} finally {
    Remove-Variable -Name LiveMockPolicies -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name SimulateTimeoutOnPolId -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name SimulateErrorOnPolId -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path $tempTestDir) {
        Get-ChildItem -Path $tempTestDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $tempTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
