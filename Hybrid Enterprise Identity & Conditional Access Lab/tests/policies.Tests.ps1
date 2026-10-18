<#
.SYNOPSIS
    Pester Test Suite: Declarative Conditional Access Policies & Schema Validation.
#>

Describe "Conditional Access Declarative Policy Validation" {
    BeforeAll {
        $policiesPath = Join-Path $PSScriptRoot "..\policies"
        $schemaPath   = Join-Path $policiesPath "schema\conditional-access.schema.json"
        $deployScript = Join-Path $PSScriptRoot "..\scripts\deployment\deploy_ca_policies.ps1"
        [void]$schemaPath
        [void]$deployScript
    }

    Context "Policy File Inventory" {
        It "Should contain all 11 required baseline policy files and schema" {
            (Test-Path $schemaPath) | Should -Be $true
            $expectedPolicies = @(
                "CAP-001-location.json",
                "CAP-002-admin-mfa.json",
                "CAP-003-risk-mfa.json",
                "CAP-004-legacy-auth.json",
                "CAP-005-session.json",
                "CAP-006-device-compliance.json",
                "CAP-007-baseline-workforce-mfa.json",
                "CAP-008-securing-security-info.json",
                "CAP-009-paw-privileged-access.json",
                "CAP-010-guest-external-controls.json",
                "CAP-012-user-risk-remediation.json"
            )

            foreach ($pol in $expectedPolicies) {
                (Test-Path (Join-Path $policiesPath $pol)) | Should -Be $true
            }
        }
    }

    Context "Schema Conformance" {
        It "Must validate all policy definitions with zero schema errors (-ValidateOnly)" {
            $null = & $deployScript -ValidateOnly
            $LASTEXITCODE | Should -Be 0
        }

        It "All policies must default to Report-only mode during staging" {
            $policyFiles = Get-ChildItem -Path $policiesPath -Filter "*.json"
            foreach ($file in $policyFiles) {
                $json = Get-Content $file.FullName -Raw | ConvertFrom-Json
                $json.state | Should -Be "enabledForReportingButNotEnforced"
            }
        }

        It "All applicable policies must exclude SEC-BreakGlass-Exclusion" {
            $excludedExemptionPolicies = @("CAP-005-session.json", "CAP-009-paw-privileged-access.json", "CAP-010-guest-external-controls.json")
            $policyFiles = Get-ChildItem -Path $policiesPath -Filter "*.json"
            
            foreach ($file in $policyFiles) {
                if ($file.Name -notin $excludedExemptionPolicies) {
                    $json = Get-Content $file.FullName -Raw | ConvertFrom-Json
                    ($json.conditions.users.excludeGroups -contains "SEC-BreakGlass-Exclusion") | Should -Be $true
                }
            }
        }
    }
}
