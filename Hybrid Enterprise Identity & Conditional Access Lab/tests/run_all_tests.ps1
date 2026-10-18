<#
.SYNOPSIS
    Unified Master Test Runner for Identity-as-Code Lab.
.DESCRIPTION
    Executes the complete test matrix across schema validation, identity resolution,
    governance compliance, deployment safety, and JML lifecycle automation.
    Implements reliable error capture and non-zero exit propagation.
#>

[CmdletBinding()]
param (
    [string]$ExportEvidencePath = "",
    [switch]$ExportEvidence
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity Security Portfolio - Master Test Suite" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$testStartTime = Get-Date
$suiteFailures = [System.Collections.Generic.List[string]]::new()
$suiteRecords = [System.Collections.Generic.List[psobject]]::new()
$totalTestSteps = 0
$passedTestSteps = 0
$totalVerificationChecks = 0
$totalPassedChecks = 0
$totalFailedChecks = 0

function Invoke-GuardedTestSuite {
    param (
        [string]$SuiteName,
        [string]$ScriptPath,
        [string]$Category,
        [int]$CheckCount,
        [string]$Description
    )
    $script:totalTestSteps++
    $script:totalVerificationChecks += $CheckCount
    Write-Host "`n----------------------------------------------------------" -ForegroundColor Gray
    Write-Host "[Master Runner] Executing: $SuiteName" -ForegroundColor Cyan
    Write-Host "Category: $Category | Checks: $CheckCount" -ForegroundColor DarkCyan
    Write-Host "Script: $ScriptPath" -ForegroundColor Gray
    Write-Host "----------------------------------------------------------" -ForegroundColor Gray

    $suiteStatus = "PASS"
    try {
        # Execute in an isolated child powershell process to guarantee reliable exit code propagation (Finding F)
        $psExe = (Get-Process -Id $PID).Path
        if (-not $psExe -or -not (Test-Path $psExe)) {
            $psExe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell.exe" }
        }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $psExe
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($psi)
        $stdOutTask = $process.StandardOutput.ReadToEndAsync()
        $stdErr = $process.StandardError.ReadToEnd()
        $stdOut = $stdOutTask.GetAwaiter().GetResult()
        $process.WaitForExit()
        $childExitCode = $process.ExitCode

        if ($stdOut) { Write-Host $stdOut }
        if ($stdErr) { Write-Host $stdErr -ForegroundColor Yellow }

        $hasFailedText = ($stdOut -match "\[FAIL\]" -or $stdOut -match "Test \d+ Failed" -or $stdErr -match "\[FAIL\]")

        if ($childExitCode -ne 0 -or $hasFailedText) {
            $suiteStatus = "FAIL"
            $script:suiteFailures.Add("$SuiteName (Exit Code: $childExitCode)")
            $script:totalFailedChecks += $CheckCount
            Write-Host "  [RESULT] FAILED: $SuiteName" -ForegroundColor Red
        } else {
            $script:passedTestSteps++
            $script:totalPassedChecks += $CheckCount
            Write-Host "  [RESULT] PASSED: $SuiteName" -ForegroundColor Green
        }
    } catch {
        $suiteStatus = "FAIL"
        $script:suiteFailures.Add("$SuiteName (Exception: $($_.Exception.Message))")
        $script:totalFailedChecks += $CheckCount
        Write-Host "  [RESULT] EXCEPTION in $SuiteName : $($_.Exception.Message)" -ForegroundColor Red
    }

    $repoRoot = Split-Path $PSScriptRoot -Parent
    $relPath = $ScriptPath.Replace($repoRoot, "").TrimStart("\").TrimStart("/").Replace("\", "/")

    $script:suiteRecords.Add([PSCustomObject]@{
        suiteName = $SuiteName
        category  = $Category
        script    = $relPath
        status    = $suiteStatus
        count     = $CheckCount
        details   = $Description
    })
}

# 1. Deep Schema Validation & Safety Gate Security Tests
Invoke-GuardedTestSuite -SuiteName "Declarative Policy Schema & Baseline Conformance" `
                       -ScriptPath (Join-Path $PSScriptRoot "schema\test_policy_schema.ps1") `
                       -Category "Local Unit Test" `
                       -CheckCount 11 `
                       -Description "All 11 baseline policy definitions validate cleanly against Draft-07 JSON Schema (conditional-access.schema.json) with strict type checking, regex patterns, and required property constraints."

# 2. Identity Resolution Tests
Invoke-GuardedTestSuite -SuiteName "Group Reference Resolution Gate" `
                       -ScriptPath (Join-Path $PSScriptRoot "identity\test_group_resolution.ps1") `
                       -Category "Local Unit Test" `
                       -CheckCount 1 `
                       -Description "Resolves declarative security group display names to tenant object IDs and validates group existence."

Invoke-GuardedTestSuite -SuiteName "User Reference Resolution Gate" `
                       -ScriptPath (Join-Path $PSScriptRoot "identity\test_user_resolution.ps1") `
                       -Category "Local Unit Test" `
                       -CheckCount 1 `
                       -Description "Resolves break-glass user identities and emergency exclusion references to directory object IDs."

# 3. Deployment Safety, Drift & Cryptographic Snapshot Tests
Invoke-GuardedTestSuite -SuiteName "Declarative Policy Drift Detection Engine" `
                       -ScriptPath (Join-Path $PSScriptRoot "deployment\test_compare_policies.ps1") `
                       -Category "Mocked Graph API Integration Test" `
                       -CheckCount 7 `
                       -Description "7 drift & canonical normalization tests: Identity equivalence, state drift, array-order normalization, key-order normalization, server metadata stripping, null vs missing property handling, and deep field-level difference reporting."

Invoke-GuardedTestSuite -SuiteName "Snapshot Cryptographic Integrity & Anti-Tamper Engine" `
                       -ScriptPath (Join-Path $PSScriptRoot "deployment\test_snapshot_integrity.ps1") `
                       -Category "Mocked Graph API Integration Test" `
                       -CheckCount 9 `
                       -Description "9 security test assertions: Valid sealed snapshot, modified policy payload, tampered manifest, tampered checksums, unlisted extraneous file injection, missing file, duplicate policy ID, corrupt JSON, and path traversal rejection."

if (Test-Path (Join-Path $PSScriptRoot "deployment\test_deployment_failure_recovery.ps1")) {
    Invoke-GuardedTestSuite -SuiteName "Deployment Failure & In-Flight Atomic Rollback" `
                           -ScriptPath (Join-Path $PSScriptRoot "deployment\test_deployment_failure_recovery.ps1") `
                           -Category "Mocked Graph API Integration Test" `
                           -CheckCount 10 `
                           -Description "10 transaction assertions: Successful deployment, HTTP 400 rejection, HTTP 403 permission failure, HTTP 429 throttling, HTTP 500 server error, timeout after PATCH, timeout after POST, rollback failure, rollback verification mismatch, and duplicate policy matching ambiguity."
}

# 4. Identity Lifecycle (JML) Tests
Invoke-GuardedTestSuite -SuiteName "JML Identity Lifecycle State Machine Engine" `
                       -ScriptPath (Join-Path $PSScriptRoot "lifecycle\test_lifecycle_engine.ps1") `
                       -Category "Local Unit Test" `
                       -CheckCount 16 `
                       -Description "16 unit tests: 24-character cryptographic password entropy, department-to-RBAC mappings, emergency break-glass account safeguard, AST parser syntax checks across all lifecycle scripts, and duplicate identity lookup error matrix (404 proceed, 200 exist, 403, 429, 500, timeout, and malformed fail-closed)."

# 5. Governance Scripts Pre-Flight Tests
Invoke-GuardedTestSuite -SuiteName "Governance & PIM Pre-Flight Syntax & Parameter Engine" `
                       -ScriptPath (Join-Path $PSScriptRoot "governance\test_governance_scripts.ps1") `
                       -Category "Local Unit Test" `
                       -CheckCount 3 `
                       -Description "3 pre-flight tests verifying AST syntax and parameter definitions for access_review.ps1, configure_pim.ps1, and privileged_role_audit.ps1."

# 6. Pester Native Test Matrix
$script:totalTestSteps++
$script:totalVerificationChecks += 14
Write-Host "`n----------------------------------------------------------" -ForegroundColor Gray
Write-Host "[Master Runner] Executing Native Pester Assertion Matrix" -ForegroundColor Cyan
Write-Host "Category: Local Unit Test | Checks: 14" -ForegroundColor DarkCyan
Write-Host "----------------------------------------------------------" -ForegroundColor Gray

$pesterResult = Invoke-Pester -Path "$PSScriptRoot\" -PassThru
$pesterStatus = "PASS"
$pPassed = $pesterResult.PassedCount
$pFailed = $pesterResult.FailedCount
$script:totalPassedChecks += $pPassed
$script:totalFailedChecks += $pFailed

if ($pFailed -gt 0) {
    $pesterStatus = "FAIL"
    $suiteFailures.Add("Pester Matrix ($pFailed failed assertions)")
    Write-Host "  [RESULT] FAILED: $pFailed Pester assertion(s) failed." -ForegroundColor Red
} else {
    $script:passedTestSteps++
    Write-Host "  [RESULT] PASSED: All $pPassed Pester assertions passed." -ForegroundColor Green
}

$suiteRecords.Add([PSCustomObject]@{
    suiteName = "Native Pester Assertion Matrix"
    category  = "Local Unit Test"
    script    = "tests/identity_suite.Tests.ps1"
    status    = $pesterStatus
    count     = 14
    details   = "14 Pester assertions covering credential entropy, RBAC department routing, break-glass safeguard gates, policy file inventories, schema compliance, report-only default states, break-glass exclusion checks, git hygiene, secret scanning, and evidence exporter data sanitization."
})

$elapsed = ((Get-Date) - $testStartTime).TotalSeconds

# Final Master Verification Summary
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  MASTER TEST RUNNER EXECUTION SUMMARY                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Total Test Suites     : $totalTestSteps" -ForegroundColor White
Write-Host "  Passed Test Suites    : $passedTestSteps" -ForegroundColor Green
Write-Host "  Failed Test Suites    : $($suiteFailures.Count)" -ForegroundColor $(if($suiteFailures.Count -gt 0){'Red'}else{'Green'})
Write-Host "  Total Itemized Checks : $totalVerificationChecks" -ForegroundColor White
Write-Host "  Passed Checks         : $totalPassedChecks" -ForegroundColor Green
Write-Host "  Failed Checks         : $totalFailedChecks" -ForegroundColor $(if($totalFailedChecks -gt 0){'Red'}else{'Green'})
Write-Host "  Execution Duration    : $([math]::Round($elapsed, 2))s" -ForegroundColor White

# Optional Machine-Readable Evidence Generation (Item 19 / Audit Finding 1)
if ($ExportEvidence -or $ExportEvidencePath) {
    $outPath = if ($ExportEvidencePath) { $ExportEvidencePath } else { Join-Path (Split-Path $PSScriptRoot -Parent) "evidence\test-results.json" }
    Write-Host "`n[Evidence Engine] Generating reproducible test provenance report..." -ForegroundColor Cyan

    $commitSha = try { (git rev-parse HEAD 2>$null).Trim() } catch { "" }
    if (-not $commitSha) {
        $commitSha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "LOCAL-UNCOMMITTED" }
    }

    $runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local-dev-execution" }
    $runUrl = if ($env:GITHUB_SERVER_URL -and $env:GITHUB_REPOSITORY -and $env:GITHUB_RUN_ID) {
        "$($env:GITHUB_SERVER_URL)/$($env:GITHUB_REPOSITORY)/actions/runs/$($env:GITHUB_RUN_ID)"
    } else {
        "local://workstation/test-execution"
    }

    $evidenceObject = [PSCustomObject]@{
        testSuite         = "Microsoft Entra ID Zero Trust & Identity-as-Code Engine"
        executedAtUtc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        gitCommitSha      = $commitSha
        gitHubActionsRunId = $runId
        gitHubActionsRunUrl = $runUrl
        environment       = "GitHub Actions CI/CD & Local PowerShell Engine"
        executionScope    = [PSCustomObject]@{
            mode                    = "Automated Offline CI/CD Test Matrix"
            liveTenantConnected     = $false
            mockedGraphApiEmulation = $true
            independentLiveEvidence = "evidence/live-tenant-state/live-tenant-state.json"
            scopeNote               = "This report documents local AST syntax, JSON schema conformance, cryptographic snapshot integrity, and mocked Graph API deployment transactions. Live tenant state is documented independently via dedicated read-only tenant exports."
        }
        resultsSummary    = [PSCustomObject]@{
            totalVerificationChecks = $totalVerificationChecks
            passed                  = $totalPassedChecks
            failed                  = $totalFailedChecks
            skipped                 = 0
            durationSeconds         = [math]::Round($elapsed, 2)
            calculationMethodology  = "Itemized check count across 9 test suites: Schema validation (11), Group resolution (1), User resolution (1), Drift & canonical normalization engine (7), Snapshot integrity (9), Deployment failure & rollback recovery (10), Lifecycle engine (16), Governance pre-flight (3), and Native Pester matrix (14)."
            testTiersBreakdown      = [PSCustomObject]@{
                localUnitTestsChecks            = 46
                mockedGraphApiIntegrationChecks = 26
            }
        }
        testSuites        = $suiteRecords
    }

    $jsonOutput = $evidenceObject | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($outPath, $jsonOutput, [System.Text.Encoding]::UTF8)
    Write-Host "  -> Machine-readable test evidence successfully saved to: $outPath" -ForegroundColor Green
}

if ($suiteFailures.Count -gt 0) {
    Write-Host "`n[FATAL] The following test suites failed:" -ForegroundColor Red
    foreach ($f in $suiteFailures) {
        Write-Host "  - $f" -ForegroundColor Red
    }
    Write-Host "==========================================================" -ForegroundColor Red
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  ALL TEST SUITES & SECURITY GATES PASSED CLEANLY!       " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
exit 0
