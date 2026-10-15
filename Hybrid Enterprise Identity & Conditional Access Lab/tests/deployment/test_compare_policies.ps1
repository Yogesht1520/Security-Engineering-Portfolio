# Test Drift Detection Logic
$compareScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\compare_policies.ps1"

Write-Host "Running Drift Detection Test..." -ForegroundColor Cyan

# Test Case 1: Identical policies (No drift)
$policyA = [PSCustomObject]@{
    displayName = "CAP-001: Test"
    state = "enabledForReportingButNotEnforced"
    conditions = [PSCustomObject]@{ users = [PSCustomObject]@{ includeUsers = @("All") } }
    grantControls = [PSCustomObject]@{ operator = "OR"; builtInControls = @("block") }
    sessionControls = [PSCustomObject]@{}
}
$policyB = [PSCustomObject]@{
    id = "guid-12345"
    displayName = "CAP-001: Test"
    state = "enabledForReportingButNotEnforced"
    createdDateTime = "2026-01-01T00:00:00Z"
    conditions = [PSCustomObject]@{ users = [PSCustomObject]@{ includeUsers = @("All") } }
    grantControls = [PSCustomObject]@{ operator = "OR"; builtInControls = @("block") }
    sessionControls = [PSCustomObject]@{}
}

$res1 = & $compareScript -LocalPolicy $policyA -LivePolicy $policyB
if ($res1.HasDrift -eq $false) {
    Write-Host "  [PASS] Test 1: Identical policies correctly report NO drift." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 1: Unexpected drift detected."
    exit 1
}

# Test Case 2: State drift (Desired Report-only, Live is Enabled)
$policyC = [PSCustomObject]@{
    id = "guid-12345"
    displayName = "CAP-001: Test"
    state = "enabled"
    conditions = [PSCustomObject]@{ users = [PSCustomObject]@{ includeUsers = @("All") } }
    grantControls = [PSCustomObject]@{ operator = "OR"; builtInControls = @("block") }
    sessionControls = [PSCustomObject]@{}
}

$res2 = & $compareScript -LocalPolicy $policyA -LivePolicy $policyC
if ($res2.HasDrift -eq $true) {
    Write-Host "  [PASS] Test 2: State drift detected successfully (Expected Report-only, Live Enabled)." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 2: Failed to detect state drift."
    exit 1
}

Write-Host "`nAll drift detection tests passed!" -ForegroundColor Green
