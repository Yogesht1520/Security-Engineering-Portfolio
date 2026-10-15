# Test Policy Schema Validation & Break-Glass Gate
$schemaScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\validate_schema.ps1"
$schemaFile   = Join-Path $PSScriptRoot "..\..\policies\schema\conditional-access.schema.json"
$deployScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\deploy_ca_policies.ps1"

. $schemaScript

Write-Host "Running Schema Validation & Gate Security Tests..." -ForegroundColor Cyan

# Test 1: All production repository policies pass schema check
try {
    & $deployScript -ValidateOnly
    if ($LASTEXITCODE -ne 0) { throw "ValidateOnly returned non-zero exit code $LASTEXITCODE" }
    Write-Host "  [PASS] Test 1: All production repository policies pass schema check." -ForegroundColor Green
} catch {
    Write-Error "  [FAIL] Test 1: Repository policies failed schema check: $($_.Exception.Message)"
    exit 1
}

# Test 2: Unsupported property is rejected (additionalProperties: false)
try {
    $invalidPolicy = [PSCustomObject]@{
        displayName = "CAP-999: Test Unsupported Property"
        state       = "enabledForReportingButNotEnforced"
        conditions  = [PSCustomObject]@{
            users = [PSCustomObject]@{
                includeUsers = @("All")
                excludeGroups = @("SEC-BreakGlass-Exclusion")
            }
            applications = [PSCustomObject]@{
                includeApplications = @("All")
            }
        }
        unsupportedExtraField = "malformed_value"
    }

    $rejected = $false
    try {
        Test-PolicyJsonSchema -JsonData $invalidPolicy -SchemaPath $schemaFile -PolicyFileName "invalid-policy.json"
    } catch {
        $rejected = $true
        Write-Host "  [PASS] Test 2: Schema engine rejected unsupported property ('unsupportedExtraField')." -ForegroundColor Green
    }

    if (-not $rejected) {
        Write-Error "  [FAIL] Test 2: Schema engine failed to reject unsupported property."
        exit 1
    }
} catch {
    Write-Error "  [FAIL] Test 2 exception: $($_.Exception.Message)"
    exit 1
}

# Test 3: Invalid type/enum is rejected
try {
    $invalidEnumPolicy = [PSCustomObject]@{
        displayName = "CAP-998: Test Invalid State Enum"
        state       = "invalidStateValue"
        conditions  = [PSCustomObject]@{
            users = [PSCustomObject]@{
                includeUsers = @("All")
                excludeGroups = @("SEC-BreakGlass-Exclusion")
            }
            applications = [PSCustomObject]@{
                includeApplications = @("All")
            }
        }
    }

    $rejected = $false
    try {
        Test-PolicyJsonSchema -JsonData $invalidEnumPolicy -SchemaPath $schemaFile -PolicyFileName "invalid-enum.json"
    } catch {
        $rejected = $true
        Write-Host "  [PASS] Test 3: Schema engine rejected invalid enum value ('invalidStateValue')." -ForegroundColor Green
    }

    if (-not $rejected) {
        Write-Error "  [FAIL] Test 3: Schema engine failed to reject invalid enum."
        exit 1
    }
} catch {
    Write-Error "  [FAIL] Test 3 exception: $($_.Exception.Message)"
    exit 1
}

# Test 4: Broad policy targeting All users without SEC-BreakGlass-Exclusion is blocked
try {
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ca_test_" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    $lockedPolicy = @{
        displayName = "CAP-997: Dangerous Lockout Policy"
        state       = "enabledForReportingButNotEnforced"
        conditions  = @{
            users = @{
                includeUsers = @("All")
                excludeGroups = @()
            }
            applications = @{
                includeApplications = @("All")
            }
        }
    }
    $lockedPolicy | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $tempDir "CAP-997-lockout.json") -Encoding utf8

    $gateTriggered = $false
    try {
        $output = & $deployScript -PoliciesPath $tempDir -ValidateOnly 2>&1
        if ($LASTEXITCODE -ne 0 -or ($output | Out-String) -match "FAIL-CLOSED GATE") {
            $gateTriggered = $true
            Write-Host "  [PASS] Test 4: Hard break-glass deployment gate terminated broad lockout policy." -ForegroundColor Green
        }
    } finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not $gateTriggered) {
        Write-Error "  [FAIL] Test 4: Broad policy without break-glass exclusion was not blocked!"
        exit 1
    }
} catch {
    Write-Error "  [FAIL] Test 4 exception: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nAll policy schema & safety gate tests PASSED!" -ForegroundColor Green
$global:LASTEXITCODE = 0
