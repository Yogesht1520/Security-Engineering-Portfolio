<#
.SYNOPSIS
    Comprehensive Production Orchestrator Integration & Recovery Test Suite.
.DESCRIPTION
    Validates end-to-end atomic deployment failure semantics by directly importing and testing
    the production Invoke-PolicyDeploymentTransaction orchestrator (from deployment_engine.ps1)
    and rollback_policies.ps1 across 10 required failure and edge-case scenarios:
    1. Successful deployment (clean completion)
    2. HTTP 400 rejection (bad request / validation failure)
    3. HTTP 403 permission failure (insufficient privileges)
    4. HTTP 429 throttling (rate limit exceeded)
    5. HTTP 500 server error (backend failure)
    6. Timeout after Graph accepted a PATCH (ambiguous update committed)
    7. Timeout after Graph accepted a POST (ambiguous create committed)
    8. Rollback failure (error during restoration)
    9. Rollback verification mismatch (post-restore config drift)
    10. Duplicate policy matching (ambiguous live matches halt rollback)
#>

[CmdletBinding()]
param ()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  TEST: Production Orchestrator Failure & Recovery Matrix " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$tempTestDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ca_fail_test_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempTestDir -Force | Out-Null

try {
    # 1. Establish Initial Baseline Policy State
    $baselinePolicies = [ordered]@{
        "pol-001" = [PSCustomObject]@{ id = "pol-001"; displayName = "CAP-001-location"; state = "disabled" }
        "pol-002" = [PSCustomObject]@{ id = "pol-002"; displayName = "CAP-002-admin-mfa"; state = "enabledForReportingButNotEnforced" }
        "pol-003" = [PSCustomObject]@{ id = "pol-003"; displayName = "CAP-003-risk-mfa"; state = "disabled" }
        "pol-004" = [PSCustomObject]@{ id = "pol-004"; displayName = "CAP-004-legacy-auth"; state = "disabled" }
        "pol-005" = [PSCustomObject]@{ id = "pol-005"; displayName = "CAP-005-session-controls"; state = "disabled" }
    }

    # Live Mock Tenant State Store
    $global:LiveMockPolicies = @{}
    function Clear-MockTenantState {
        $global:LiveMockPolicies.Clear()
        foreach ($k in $baselinePolicies.Keys) {
            $b = $baselinePolicies[$k]
            $global:LiveMockPolicies[$k] = [PSCustomObject]@{
                id          = $b.id
                displayName = $b.displayName
                state       = $b.state
            }
        }
        $global:FaultInjectHttpCode = 0
        $global:FaultInjectErrorOnPolId = $null
        $global:FaultInjectTimeoutPatch = $false
        $global:FaultInjectTimeoutPost = $false
        $global:FaultInjectRollbackFail = $false
        $global:FaultInjectVerifyMismatch = $false
        $global:InRollbackMode = $false
    }
    Clear-MockTenantState

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
                value             = $pList
                '@odata.nextLink' = $null
            }
        }

        # 3. PATCH policy
        if ($Method -eq "PATCH" -and $Uri -match "/policies/([^/?]+)$") {
            $polId = $Matches[1]

            # Rollback fault injection (Scenario 8)
            if ($global:FaultInjectRollbackFail -and $global:InRollbackMode) {
                throw "Microsoft Graph API: 500 Internal Server Error (Rollback restore PATCH failed)"
            }

            # Timeout after PATCH simulation (Scenario 6)
            if ($global:FaultInjectTimeoutPatch) {
                $global:FaultInjectTimeoutPatch = $false
                $bObj = $Body | ConvertFrom-Json
                if ($global:LiveMockPolicies.ContainsKey($polId)) {
                    $global:LiveMockPolicies[$polId].state = $bObj.state
                }
                throw [System.Net.WebException]::new("The operation has timed out: Connection dropped after server committed PATCH.")
            }

            # Specific policy error injection
            if ($global:FaultInjectErrorOnPolId -eq $polId) {
                $global:InRollbackMode = $true
                throw "Microsoft Graph API: 400 Bad Request on $polId"
            }

            # HTTP Error simulation (Scenarios 2, 3, 4, 5)
            if ($global:FaultInjectHttpCode -gt 0) {
                $code = $global:FaultInjectHttpCode
                $global:FaultInjectHttpCode = 0
                $global:InRollbackMode = $true
                switch ($code) {
                    400 { throw "Microsoft Graph API: 400 Bad Request (Invalid condition combination)" }
                    403 { throw "Microsoft Graph API: 403 Forbidden (Insufficient privileges Policy.ReadWrite.ConditionalAccess)" }
                    429 { throw "Microsoft Graph API: 429 Too Many Requests (Rate limit exceeded, retry-after 30)" }
                    500 { throw "Microsoft Graph API: 500 Internal Server Error (Transient backend fault)" }
                }
            }

            if (-not $global:LiveMockPolicies.ContainsKey($polId)) {
                throw "Policy '$polId' not found in live mock tenant."
            }
            $bodyObj = $Body | ConvertFrom-Json

            if ($global:FaultInjectVerifyMismatch -and $global:InRollbackMode) {
                # Purposely leave state different from snapshot to trigger verification mismatch (Scenario 9)
                $global:LiveMockPolicies[$polId].state = "tamperedState"
            } else {
                $global:LiveMockPolicies[$polId].state = $bodyObj.state
            }

            return [PSCustomObject]@{ id = $polId; state = $global:LiveMockPolicies[$polId].state }
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

            # Timeout after POST simulation (Scenario 7)
            if ($global:FaultInjectTimeoutPost) {
                $global:FaultInjectTimeoutPost = $false
                $global:InRollbackMode = $true
                throw [System.Net.WebException]::new("The operation has timed out: Connection dropped after server committed POST.")
            }

            return $newPol
        }

        # 5. DELETE policy
        if ($Method -eq "DELETE" -and $Uri -match "/policies/([^/?]+)$") {
            $polId = $Matches[1]
            if ($global:FaultInjectRollbackFail -and $global:InRollbackMode) {
                throw "Microsoft Graph API: 500 Internal Server Error (Rollback DELETE failed)"
            }
            if ($global:LiveMockPolicies.ContainsKey($polId)) {
                $global:LiveMockPolicies.Remove($polId)
            }
            return $null
        }
    }

    # 2. Generate Verified Pre-Deployment Baseline Snapshot
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

    # 3. Import Production Deployment Engine
    $engineScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\deployment_engine.ps1"
    . $engineScript
    $rollbackScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\rollback_policies.ps1"
    $reportsDir = Join-Path $tempTestDir "reports"

    # =========================================================================
    # SCENARIO 1: Successful Deployment
    # =========================================================================
    Write-Host "`n[Scenario 1] Testing Successful Deployment..." -ForegroundColor Cyan
    Clear-MockTenantState
    $actions1 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-002-admin-mfa"; PolicyId = "pol-002"; Payload = @{ displayName = "CAP-002-admin-mfa"; state = "enabled" } }
    )
    $res1 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions1 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res1.TransactionState -ne "Completed") { throw "Scenario 1 Failed: Expected 'Completed', got '$($res1.TransactionState)'" }
    if ($global:LiveMockPolicies["pol-001"].state -ne "enabled") { throw "Scenario 1 Failed: pol-001 not updated" }
    Write-Host "  -> PASS: Successful deployment executed cleanly." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 2: HTTP 400 Rejection
    # =========================================================================
    Write-Host "`n[Scenario 2] Testing HTTP 400 Rejection..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectHttpCode = 400
    $actions2 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
    )
    $res2 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions2 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res2.TransactionState -ne "FailedAndClean" -and $res2.TransactionState -ne "FailedAndRolledBack") { throw "Scenario 2 Failed: Expected 'FailedAndClean' or 'FailedAndRolledBack', got '$($res2.TransactionState)'" }
    if ($res2.Receipt.FailureReason -notmatch "400") { throw "Scenario 2 Failed: Expected 400 in reason" }
    Write-Host "  -> PASS: HTTP 400 rejection caught and cleanly rolled back." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 3: HTTP 403 Permission Failure
    # =========================================================================
    Write-Host "`n[Scenario 3] Testing HTTP 403 Permission Failure..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectHttpCode = 403
    $actions3 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
    )
    $res3 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions3 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res3.TransactionState -ne "FailedAndClean" -and $res3.TransactionState -ne "FailedAndRolledBack") { throw "Scenario 3 Failed: Expected failure state, got '$($res3.TransactionState)'" }
    if ($res3.Receipt.FailureReason -notmatch "403") { throw "Scenario 3 Failed: Expected 403 in reason" }
    Write-Host "  -> PASS: HTTP 403 permission failure caught and handled." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 4: HTTP 429 Throttling
    # =========================================================================
    Write-Host "`n[Scenario 4] Testing HTTP 429 Throttling..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectHttpCode = 429
    $actions4 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
    )
    $res4 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions4 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res4.TransactionState -ne "FailedAndClean" -and $res4.TransactionState -ne "FailedAndRolledBack") { throw "Scenario 4 Failed: Expected failure state, got '$($res4.TransactionState)'" }
    if ($res4.Receipt.FailureReason -notmatch "429") { throw "Scenario 4 Failed: Expected 429 in reason" }
    Write-Host "  -> PASS: HTTP 429 throttling halted transaction cleanly." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 5: HTTP 500 Server Error
    # =========================================================================
    Write-Host "`n[Scenario 5] Testing HTTP 500 Server Error..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectHttpCode = 500
    $actions5 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
    )
    $res5 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions5 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res5.TransactionState -ne "FailedAndClean" -and $res5.TransactionState -ne "FailedAndRolledBack") { throw "Scenario 5 Failed: Expected failure state, got '$($res5.TransactionState)'" }
    if ($res5.Receipt.FailureReason -notmatch "500") { throw "Scenario 5 Failed: Expected 500 in reason" }
    Write-Host "  -> PASS: HTTP 500 server error triggered fail-safe rollback." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 6: Timeout after Graph Accepted a PATCH (Ambiguous Update)
    # =========================================================================
    Write-Host "`n[Scenario 6] Testing Timeout after Graph accepted a PATCH..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectTimeoutPatch = $true
    $actions6 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
    )
    $res6 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions6 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res6.TransactionState -ne "FailedAndRolledBack") { throw "Scenario 6 Failed: Expected 'FailedAndRolledBack', got '$($res6.TransactionState)'" }
    if ($res6.Receipt.MutationsApplied -lt 1) { throw "Scenario 6 Failed: Ambiguous write was not detected as applied" }
    if ($global:LiveMockPolicies["pol-001"].state -ne "disabled") { throw "Scenario 6 Failed: pol-001 not restored to disabled baseline" }
    Write-Host "  -> PASS: Ambiguous PATCH write detected, accounted for, and restored." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 7: Timeout after Graph Accepted a POST (Ambiguous Create)
    # =========================================================================
    Write-Host "`n[Scenario 7] Testing Timeout after Graph accepted a POST..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectTimeoutPost = $true
    $actions7 = @(
        [PSCustomObject]@{ Action = "Create"; DisplayName = "CAP-999-new-policy"; PolicyId = $null; Payload = @{ displayName = "CAP-999-new-policy"; state = "enabled" } }
    )

    # 7A. Default Enterprise Policy (FailClosedPreserve): Policy preserved, automatic deletion halted, PendingVerification
    $res7A = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions7 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir -AmbiguousPostPolicy "FailClosedPreserve"
    if ($res7A.TransactionState -ne "PendingVerification") { throw "Scenario 7A Failed: Expected 'PendingVerification', got '$($res7A.TransactionState)'" }
    $preserveCheck = @($global:LiveMockPolicies.Values | Where-Object { $_.displayName -eq "CAP-999-new-policy" })
    if ($preserveCheck.Count -ne 1) { throw "Scenario 7A Failed: Ambiguously created policy was deleted instead of being preserved for operator verification" }

    # 7B. Automated Lab / CI Policy (AutoPurgeCorrelated): Strict correlation purges orphan
    Clear-MockTenantState
    $global:FaultInjectTimeoutPost = $true
    $res7B = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions7 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir -AmbiguousPostPolicy "AutoPurgeCorrelated"
    if ($res7B.TransactionState -ne "FailedAndRolledBack") { throw "Scenario 7B Failed: Expected 'FailedAndRolledBack', got '$($res7B.TransactionState)'" }
    $orphanCheck = @($global:LiveMockPolicies.Values | Where-Object { $_.displayName -eq "CAP-999-new-policy" })
    if ($orphanCheck.Count -gt 0) { throw "Scenario 7B Failed: Ambiguously created policy was not purged under AutoPurgeCorrelated" }
    Write-Host "  -> PASS: Ambiguous POST creation verified: preserved under FailClosedPreserve and purged under AutoPurgeCorrelated." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 8: Rollback Failure
    # =========================================================================
    Write-Host "`n[Scenario 8] Testing Rollback Failure..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectErrorOnPolId = "pol-002"
    $global:FaultInjectRollbackFail = $true
    $actions8 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-002-admin-mfa"; PolicyId = "pol-002"; Payload = @{ displayName = "CAP-002-admin-mfa"; state = "enabled" } }
    )
    $res8 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions8 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res8.TransactionState -ne "RollbackFailed") { throw "Scenario 8 Failed: Expected 'RollbackFailed', got '$($res8.TransactionState)'" }
    Write-Host "  -> PASS: Rollback failure correctly logged as 'RollbackFailed'." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 9: Rollback Verification Mismatch
    # =========================================================================
    Write-Host "`n[Scenario 9] Testing Rollback Verification Mismatch..." -ForegroundColor Cyan
    Clear-MockTenantState
    $global:FaultInjectErrorOnPolId = "pol-002"
    $global:FaultInjectVerifyMismatch = $true
    $actions9 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-002-admin-mfa"; PolicyId = "pol-002"; Payload = @{ displayName = "CAP-002-admin-mfa"; state = "enabled" } }
    )
    $res9 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions9 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res9.TransactionState -ne "RollbackFailed") { throw "Scenario 9 Failed: Expected 'RollbackFailed' due to verification mismatch, got '$($res9.TransactionState)'" }
    Write-Host "  -> PASS: Verification mismatch caught and halted." -ForegroundColor Green

    # =========================================================================
    # SCENARIO 10: Duplicate Policy Matching Ambiguity
    # =========================================================================
    Write-Host "`n[Scenario 10] Testing Duplicate Policy Matching Ambiguity..." -ForegroundColor Cyan
    Clear-MockTenantState
    # Add a duplicate policy with the same display name as pol-001
    $global:LiveMockPolicies["pol-001-dup"] = [PSCustomObject]@{
        id          = "pol-001-dup"
        displayName = "CAP-001-location"
        state       = "disabled"
    }
    # Fail pol-002 to trigger rollback of pol-001 where duplicate matches exist in live tenant
    $global:FaultInjectErrorOnPolId = "pol-002"
    $actions10 = @(
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-001-location"; PolicyId = "pol-001"; Payload = @{ displayName = "CAP-001-location"; state = "enabled" } }
        [PSCustomObject]@{ Action = "Update"; DisplayName = "CAP-002-admin-mfa"; PolicyId = "pol-002"; Payload = @{ displayName = "CAP-002-admin-mfa"; state = "enabled" } }
    )
    $res10 = Invoke-PolicyDeploymentTransaction -ActionsToTake $actions10 -SnapshotId $snapshotTimestamp -RollbackScript $rollbackScript -ReceiptsDirectory $reportsDir -SnapshotsDir $snapshotsBaseDir
    if ($res10.TransactionState -ne "RollbackFailed") { throw "Scenario 10 Failed: Expected 'RollbackFailed' due to duplicate match ambiguity, got '$($res10.TransactionState)'" }
    Write-Host "  -> PASS: Duplicate policy matching ambiguity rejected fail-closed." -ForegroundColor Green

    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  ALL 10 PRODUCTION ORCHESTRATOR SCENARIOS PASSED CLEANLY!" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    exit 0
} catch {
    Write-Error "Deployment Failure Recovery Test Failed: $($_.Exception.Message)"
    exit 1
} finally {
    Remove-Variable -Name LiveMockPolicies -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name FaultInjectHttpCode -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name FaultInjectErrorOnPolId -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name FaultInjectTimeoutPatch -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name FaultInjectTimeoutPost -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name FaultInjectRollbackFail -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name FaultInjectVerifyMismatch -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name InRollbackMode -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path $tempTestDir) {
        Get-ChildItem -Path $tempTestDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $tempTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
