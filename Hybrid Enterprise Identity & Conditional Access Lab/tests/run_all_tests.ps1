<#
.SYNOPSIS
    Unified Master Test Runner for Identity-as-Code Lab.
.DESCRIPTION
    Executes the complete test matrix across schema validation, identity resolution,
    governance compliance, deployment safety, and JML lifecycle automation.
    Implements reliable error capture and non-zero exit propagation.
#>

[CmdletBinding()]
param ()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity Security Portfolio - Master Test Suite" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$testStartTime = Get-Date
$suiteFailures = [System.Collections.Generic.List[string]]::new()
$totalTestSteps = 0
$passedTestSteps = 0

function Invoke-GuardedTestSuite {
    param (
        [string]$SuiteName,
        [string]$ScriptPath
    )
    $script:totalTestSteps++
    Write-Host "`n----------------------------------------------------------" -ForegroundColor Gray
    Write-Host "[Master Runner] Executing: $SuiteName" -ForegroundColor Cyan
    Write-Host "Script: $ScriptPath" -ForegroundColor Gray
    Write-Host "----------------------------------------------------------" -ForegroundColor Gray

    try {
        # Execute in an isolated child powershell process to guarantee reliable exit code propagation (Finding F)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($psi)
        $stdOut = $process.StandardOutput.ReadToEnd()
        $stdErr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $childExitCode = $process.ExitCode

        if ($stdOut) { Write-Host $stdOut }
        if ($stdErr) { Write-Host $stdErr -ForegroundColor Yellow }

        $hasFailedText = ($stdOut -match "\[FAIL\]" -or $stdOut -match "Test \d+ Failed" -or $stdErr -match "\[FAIL\]")

        if ($childExitCode -ne 0 -or $hasFailedText) {
            $script:suiteFailures.Add("$SuiteName (Exit Code: $childExitCode)")
            Write-Host "  [RESULT] FAILED: $SuiteName" -ForegroundColor Red
        } else {
            $script:passedTestSteps++
            Write-Host "  [RESULT] PASSED: $SuiteName" -ForegroundColor Green
        }
    } catch {
        $script:suiteFailures.Add("$SuiteName (Exception: $($_.Exception.Message))")
        Write-Host "  [RESULT] EXCEPTION in $SuiteName : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 1. Deep Schema Validation & Safety Gate Security Tests
Invoke-GuardedTestSuite -SuiteName "Schema Validation & Hard Break-Glass Safety Gates" `
                       -ScriptPath (Join-Path $PSScriptRoot "schema\test_policy_schema.ps1")

# 2. Identity Resolution Tests
Invoke-GuardedTestSuite -SuiteName "Group Reference Resolution Gate" `
                       -ScriptPath (Join-Path $PSScriptRoot "identity\test_group_resolution.ps1")

Invoke-GuardedTestSuite -SuiteName "User Reference Resolution Gate" `
                       -ScriptPath (Join-Path $PSScriptRoot "identity\test_user_resolution.ps1")

# 3. Deployment Safety, Drift & Cryptographic Snapshot Tests
Invoke-GuardedTestSuite -SuiteName "Declarative Policy Drift Detection Engine" `
                       -ScriptPath (Join-Path $PSScriptRoot "deployment\test_compare_policies.ps1")

Invoke-GuardedTestSuite -SuiteName "Cryptographic SHA-256 Snapshot Integrity Engine" `
                       -ScriptPath (Join-Path $PSScriptRoot "deployment\test_snapshot_integrity.ps1")

if (Test-Path (Join-Path $PSScriptRoot "deployment\test_deployment_failure_recovery.ps1")) {
    Invoke-GuardedTestSuite -SuiteName "Deployment Failure & Rollback Transaction Engine" `
                           -ScriptPath (Join-Path $PSScriptRoot "deployment\test_deployment_failure_recovery.ps1")
}

# 4. Identity Lifecycle (JML) Tests
Invoke-GuardedTestSuite -SuiteName "Identity Lifecycle JML State-Machine Engine" `
                       -ScriptPath (Join-Path $PSScriptRoot "lifecycle\test_lifecycle_engine.ps1")

# 5. Governance Scripts Pre-Flight Tests
Invoke-GuardedTestSuite -SuiteName "PIM & Governance Scripts Pre-Flight Syntax & Parameter Checks" `
                       -ScriptPath (Join-Path $PSScriptRoot "governance\test_governance_scripts.ps1")

# 6. Pester Native Test Matrix
$script:totalTestSteps++
Write-Host "`n----------------------------------------------------------" -ForegroundColor Gray
Write-Host "[Master Runner] Executing Native Pester Assertion Matrix" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------" -ForegroundColor Gray

$pesterResult = Invoke-Pester -Path "$PSScriptRoot\" -PassThru
if ($pesterResult.FailedCount -gt 0) {
    $suiteFailures.Add("Pester Matrix ($($pesterResult.FailedCount) failed assertions)")
    Write-Host "  [RESULT] FAILED: $($pesterResult.FailedCount) Pester assertion(s) failed." -ForegroundColor Red
} else {
    $script:passedTestSteps++
    Write-Host "  [RESULT] PASSED: All $($pesterResult.PassedCount) Pester assertions passed." -ForegroundColor Green
}

$elapsed = ((Get-Date) - $testStartTime).TotalSeconds

# Final Master Verification Summary
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  MASTER TEST RUNNER EXECUTION SUMMARY                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Total Suites / Checks : $totalTestSteps" -ForegroundColor White
Write-Host "  Passed Suites / Checks: $passedTestSteps" -ForegroundColor Green
Write-Host "  Failed Suites / Checks: $($suiteFailures.Count)" -ForegroundColor $(if($suiteFailures.Count -gt 0){'Red'}else{'Green'})
Write-Host "  Execution Duration    : $([math]::Round($elapsed, 2))s" -ForegroundColor White

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
