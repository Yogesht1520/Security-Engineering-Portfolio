# Test Policy Schema Validation Logic
$deployScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\deploy_ca_policies.ps1"

Write-Host "Running Schema Validation Unit Tests..." -ForegroundColor Cyan

# Test 1: Real policies in repo must all pass schema validation
try {
    & $deployScript -ValidateOnly -ErrorAction Stop
    Write-Host "  [PASS] Test 1: All production repository policies pass schema check." -ForegroundColor Green
} catch {
    Write-Error "  [FAIL] Test 1: Repository policies failed schema check: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nAll policy schema tests passed!" -ForegroundColor Green
