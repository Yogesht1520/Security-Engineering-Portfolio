<#
.SYNOPSIS
    Pester Test Suite: Repository Secret Scanning & Hygiene Gate.
#>

Describe "Repository Hygiene & Secret Scanning" {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

    Context "Git Hygiene & Secrets Check" {
        It "Must not contain live secrets files committed to git" {
            $prohibitedFiles = @(
                "config\tenant.json",
                "config\environment.json",
                "config\identity-mapping.json"
            )

            foreach ($file in $prohibitedFiles) {
                (Test-Path (Join-Path $repoRoot $file)) | Should Be $false
            }
        }

        It "All template files must exist in config directory" {
            (Test-Path (Join-Path $repoRoot "config\tenant.example.json")) | Should Be $true
            (Test-Path (Join-Path $repoRoot "config\environment.example.json")) | Should Be $true
            (Test-Path (Join-Path $repoRoot "config\identity-mapping.example.json")) | Should Be $true
        }

        It "Scripts must not contain hardcoded production secrets or private keys" {
            $scriptFiles = Get-ChildItem -Path (Join-Path $repoRoot "scripts") -Recurse -Filter "*.ps1"
            $forbiddenPatterns = @(
                "client_secret\s*=\s*['`"][a-zA-Z0-9_\-~]{20,}['`"]",
                "BEGIN RSA PRIVATE KEY",
                "BEGIN PRIVATE KEY"
            )

            foreach ($script in $scriptFiles) {
                $content = Get-Content $script.FullName -Raw
                foreach ($pattern in $forbiddenPatterns) {
                    ($content -match $pattern) | Should Be $false
                }
            }
        }
    }
}
