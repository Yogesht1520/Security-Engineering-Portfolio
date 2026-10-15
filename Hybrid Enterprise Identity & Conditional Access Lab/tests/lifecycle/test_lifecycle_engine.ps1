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

Write-Host "`nAll Identity Lifecycle unit tests PASSED!" -ForegroundColor Green
