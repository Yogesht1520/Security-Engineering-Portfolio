<#
.SYNOPSIS
    Unified Master Test Runner for Identity-as-Code Lab.
.DESCRIPTION
    Executes the complete test matrix across schema validation, identity resolution,
    governance compliance, and JML lifecycle automation.
#>

[CmdletBinding()]
param ()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity Security Portfolio - Master Test Suite" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$testStartTime = Get-Date

Write-Host "`n[Suite 1/4] Running Deep Schema Validation & Safety Gate Security Tests..." -ForegroundColor Yellow
& "$PSScriptRoot\schema\test_policy_schema.ps1"
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n[Suite 2/4] Running Identity Resolution, Drift & Cryptographic Snapshot Tests..." -ForegroundColor Yellow
& "$PSScriptRoot\identity\test_group_resolution.ps1"
& "$PSScriptRoot\identity\test_user_resolution.ps1"
& "$PSScriptRoot\deployment\test_compare_policies.ps1"
& "$PSScriptRoot\deployment\test_snapshot_integrity.ps1"

Write-Host "`n[Suite 3/4] Running Identity Lifecycle (JML) Tests..." -ForegroundColor Yellow
& "$PSScriptRoot\lifecycle\test_lifecycle_engine.ps1"

Write-Host "`n[Suite 4/4] Running Governance Scripts Pre-Flight Tests..." -ForegroundColor Yellow
& "$PSScriptRoot\governance\test_governance_scripts.ps1"

Write-Host "`n[Pester Matrix] Executing Native Pester Tests..." -ForegroundColor Yellow
Invoke-Pester -Path "$PSScriptRoot\"

$elapsed = ((Get-Date) - $testStartTime).TotalSeconds
Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  ALL TEST SUITES PASSED! Execution time: $([math]::Round($elapsed, 2))s" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
