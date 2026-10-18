# Identity Lifecycle Engine Unit Tests
Write-Host "Running Identity Lifecycle Unit Tests..." -ForegroundColor Cyan

$commonDir = Join-Path $PSScriptRoot "..\..\identity-lifecycle\common"
. (Join-Path $commonDir "identity_validation.ps1")
. (Join-Path $commonDir "audit_logger.ps1")

# Test 1: Password Generation Complexity
$tempPass = New-SecureTemporaryPassword -Length 24
$hasUpper = $tempPass -cmatch "[A-Z]"
$hasLower = $tempPass -cmatch "[a-z]"
$hasDigit = $tempPass -match "[0-9]"
$hasSpecial = $tempPass -match "[^a-zA-Z0-9]"

if ($tempPass.Length -eq 24 -and $hasUpper -and $hasLower -and $hasDigit -and $hasSpecial) {
    Write-Host "  [PASS] Test 1: High-entropy password meets complexity requirements." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 1: Generated password did not meet complexity criteria: $tempPass"
    exit 1
}

# Test 2: RBAC Department Mapping
$adminGroup = Get-RbacGroupForDepartment -Department "Information Security"
$contractorGroup = Get-RbacGroupForDepartment -Department "External Contractors"
$standardGroup = Get-RbacGroupForDepartment -Department "Finance"

if ($adminGroup -eq "SEC-Admins" -and $contractorGroup -eq "SEC-Contractors" -and $standardGroup -eq "SEC-StandardUsers") {
    Write-Host "  [PASS] Test 2: Department-to-RBAC group mapping functions correctly." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 2: Incorrect RBAC mapping output: Admins=$adminGroup, Contractors=$contractorGroup, Standard=$standardGroup"
    exit 1
}

# Test 3: Safeguard Gates on Emergency Accounts
$caught = $false
try {
    Assert-SafeIdentityTarget -UserPrincipalName "emergency-admin-01@domain.com"
} catch {
    $caught = $true
}

if ($caught) {
    Write-Host "  [PASS] Test 3: Safeguard gate successfully blocked action on emergency break-glass account." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 3: Safeguard failed to block action on emergency break-glass account!"
    exit 1
}

# Test 4: Syntax Check for all Lifecycle Scripts
$lifecycleScripts = Get-ChildItem -Path "$PSScriptRoot\..\..\identity-lifecycle" -Recurse -Filter "*.ps1"
foreach ($s in $lifecycleScripts) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($s.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -eq 0) {
        Write-Host "  [PASS] Test 4: Syntax valid for $($s.Name)" -ForegroundColor Green
    } else {
        Write-Error "  [FAIL] Test 4: Syntax error in $($s.Name) at line $($errors[0].Extent.StartLineNumber): $($errors[0].Message) (Token: '$($errors[0].Extent.Text)')"
        exit 1
    }
}

# =========================================================================
# Duplicate Identity Check Error Matrix Tests (Finding B)
# =========================================================================
$global:MockGraphErrorMode = "None"
function Invoke-MockMgGraphRequestDuplicateCheck {
    param (
        [string]$Method = "GET",
        [string]$Uri,
        [string]$Body,
        [string]$ContentType,
        [string]$OutputType = "PSObject"
    )
    [void]$ContentType
    [void]$OutputType
    [void]$Body
    [void]$Method
    [void]$Uri

    switch ($global:MockGraphErrorMode) {
        "404" {
            throw "Microsoft Graph API: 404 Not Found (ResourceNotFound: User does not exist)"
        }
        "200" {
            return [PSCustomObject]@{ id = "user-guid-001"; userPrincipalName = "existing@tenant.com" }
        }
        "403" {
            throw "Microsoft Graph API: 403 Forbidden (Authorization_RequestDenied: Insufficient privileges)"
        }
        "429" {
            throw "Microsoft Graph API: 429 Too Many Requests (Rate limit exceeded, retry-after 30)"
        }
        "500" {
            throw "Microsoft Graph API: 500 Internal Server Error (GeneralException: Backend service fault)"
        }
        "Timeout" {
            throw [System.Net.WebException]::new("The operation has timed out: Network connection lost during user query.")
        }
        "Malformed" {
            throw "Unrecognized non-HTTP error text without status code"
        }
        Default {
            throw "Microsoft Graph API: 404 ResourceNotFound"
        }
    }
}

Set-Item -Path "function:Invoke-MgGraphRequest" -Value (Get-Command Invoke-MockMgGraphRequestDuplicateCheck).ScriptBlock

# Test 5: Confirmed 404 (ResourceNotFound) -> Exists = $false (proceed)
$global:MockGraphErrorMode = "404"
$res404 = Test-UserPrincipalNameExistence -UserPrincipalName "newuser@tenant.com"
if ($res404.Exists -eq $false) {
    Write-Host "  [PASS] Test 5: Confirmed 404 ResourceNotFound correctly reports non-existence (proceed)." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 5: 404 was not handled properly."
    exit 1
}

# Test 6: Confirmed 200 (Existing user) -> Exists = $true (halt)
$global:MockGraphErrorMode = "200"
$res200 = Test-UserPrincipalNameExistence -UserPrincipalName "existing@tenant.com"
if ($res200.Exists -eq $true -and $res200.User.id -eq "user-guid-001") {
    Write-Host "  [PASS] Test 6: Existing identity correctly detected (halt provisioning)." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 6: Existing identity was not detected."
    exit 1
}

# Test 7: HTTP 403 Forbidden -> Throws exception (fail-closed)
$global:MockGraphErrorMode = "403"
$threw403 = $false
try {
    Test-UserPrincipalNameExistence -UserPrincipalName "test@tenant.com"
} catch {
    $threw403 = $_.Exception.Message -match "403" -or $_.Exception.Message -match "Directory query failed"
}
if ($threw403) {
    Write-Host "  [PASS] Test 7: HTTP 403 Forbidden triggers fail-closed exception." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 7: HTTP 403 failed to throw fail-closed exception!"
    exit 1
}

# Test 8: HTTP 429 Rate Limiting -> Throws exception (fail-closed)
$global:MockGraphErrorMode = "429"
$threw429 = $false
try {
    Test-UserPrincipalNameExistence -UserPrincipalName "test@tenant.com"
} catch {
    $threw429 = $_.Exception.Message -match "429" -or $_.Exception.Message -match "Directory query failed"
}
if ($threw429) {
    Write-Host "  [PASS] Test 8: HTTP 429 Throttling triggers fail-closed exception." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 8: HTTP 429 failed to throw fail-closed exception!"
    exit 1
}

# Test 9: HTTP 500 Backend Error -> Throws exception (fail-closed)
$global:MockGraphErrorMode = "500"
$threw500 = $false
try {
    Test-UserPrincipalNameExistence -UserPrincipalName "test@tenant.com"
} catch {
    $threw500 = $_.Exception.Message -match "500" -or $_.Exception.Message -match "Directory query failed"
}
if ($threw500) {
    Write-Host "  [PASS] Test 9: HTTP 500 Server Error triggers fail-closed exception." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 9: HTTP 500 failed to throw fail-closed exception!"
    exit 1
}

# Test 10: Connection Timeout -> Throws exception (fail-closed)
$global:MockGraphErrorMode = "Timeout"
$threwTimeout = $false
try {
    Test-UserPrincipalNameExistence -UserPrincipalName "test@tenant.com"
} catch {
    $threwTimeout = $_.Exception.Message -match "timed out" -or $_.Exception.Message -match "Directory query failed"
}
if ($threwTimeout) {
    Write-Host "  [PASS] Test 10: Connection timeout triggers fail-closed exception." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 10: Timeout failed to throw fail-closed exception!"
    exit 1
}

# Test 11: Malformed Error Response -> Throws exception (fail-closed)
$global:MockGraphErrorMode = "Malformed"
$threwMalformed = $false
try {
    Test-UserPrincipalNameExistence -UserPrincipalName "test@tenant.com"
} catch {
    $threwMalformed = $_.Exception.Message -match "Directory query failed"
}
if ($threwMalformed) {
    Write-Host "  [PASS] Test 11: Malformed error response triggers fail-closed exception." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 11: Malformed response failed to throw fail-closed exception!"
    exit 1
}

Write-Host "`nAll 11 Identity Lifecycle unit tests PASSED!" -ForegroundColor Green

