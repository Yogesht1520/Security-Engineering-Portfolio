# Test User Reference Resolution Logic
$userResolverScript = Join-Path $PSScriptRoot "..\..\scripts\identity\resolve_users.ps1"

Write-Host "Running User Reference Resolution Tests..." -ForegroundColor Cyan

# Test 1: Special Graph keywords pass-through
$res1 = & $userResolverScript -UserReferences @("All", "GuestsOrExternalUsers") -FailOnUnresolved $true
if ($res1.ResolvedIds -contains "All" -and $res1.ResolvedIds -contains "GuestsOrExternalUsers") {
    Write-Host "  [PASS] Test 1: Graph special keywords ('All', 'GuestsOrExternalUsers') pass through." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 1: Special keywords failed to pass through."
    exit 1
}

# Test 2: Unresolved placeholders (e.g. 'emergency-admin-id') fail closed
$failedClosed = $false
try {
    & $userResolverScript -UserReferences @("emergency-admin-id") -FailOnUnresolved $true -ErrorAction Stop
} catch {
    $failedClosed = $true
}

if ($failedClosed) {
    Write-Host "  [PASS] Test 2: Placeholder 'emergency-admin-id' was successfully caught and blocked." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 2: Placeholder was not blocked!"
    exit 1
}

Write-Host "`nAll user resolution tests passed!" -ForegroundColor Green
