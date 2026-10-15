# Governance Scripts Unit & Syntax Test
Write-Host "Running Governance Scripts Pre-Flight Tests..." -ForegroundColor Cyan

$govScripts = Get-ChildItem -Path "$PSScriptRoot\..\..\scripts\governance" -Filter "*.ps1"

foreach ($script in $govScripts) {
    try {
        $errors = $null
        $tokens = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors) | Out-Null
        if ($errors.Count -eq 0) {
            Write-Host "  [PASS] Syntax check passed: $($script.Name)" -ForegroundColor Green
        } else {
            Write-Error "  [FAIL] Syntax errors in $($script.Name): $($errors[0].Message)"
            exit 1
        }
    } catch {
        Write-Error "  [FAIL] Failed parsing $($script.Name): $_"
        exit 1
    }
}

Write-Host "`nAll governance scripts passed syntax and parsing tests!" -ForegroundColor Green
