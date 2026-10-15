# Test Group Resolution Logic
$resolverScript = Join-Path $PSScriptRoot "..\..\scripts\identity\resolve_groups.ps1"

Write-Host "Running Group Reference Resolution Tests..." -ForegroundColor Cyan

# Test 1: Valid GUID pass-through
$validGuid = "10a34fab-c98d-4a85-84e9-42b92e96fe82"
$res1 = & $resolverScript -GroupNames @($validGuid) -FailOnUnresolved $true
if ($res1.ResolvedIds -contains $validGuid -and $res1.Success -eq $true) {
    Write-Host "  [PASS] Test 1: Valid GUID passes through directly." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 1: Valid GUID was not passed through."
    exit 1
}

# Test 2: Unresolved group fails closed when FailOnUnresolved is true
$failedClosed = $false
try {
    & $resolverScript -GroupNames @("NON-EXISTENT-SECURITY-GROUP") -FailOnUnresolved $true -ErrorAction Stop
} catch {
    $failedClosed = $true
}

if ($failedClosed) {
    Write-Host "  [PASS] Test 2: Unresolved group correctly aborted execution (Fail-Closed safety gate)." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 2: Unresolved group did not fail closed!"
    exit 1
}

Write-Host "`nAll group resolution tests passed!" -ForegroundColor Green
