<#
.SYNOPSIS
    Pester Test Suite: Repository Secret Scanning & Hygiene Gate.
#>

Describe "Repository Hygiene & Secret Scanning" {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
        . (Join-Path $repoRoot "scripts\deployment\evidence_sanitizer.ps1")
    }

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

    Context "Evidence Sanitization & Data Masking" {

        It "Must sanitize all sensitive identifier types by invoking the production ConvertTo-SanitizedJson function" {
            $sampleRawObject = [PSCustomObject]@{
                id                = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
                tenantId          = "11111111-2222-3333-4444-555555555555"
                principalId       = "99999999-8888-7777-6666-555555555555"
                roleDefinitionId  = "88888888-7777-6666-5555-444444444444"
                userPrincipalName = "admin.secops@mycorp.onmicrosoft.com"
                externalEmail     = "contractor.john@external-vendor.com"
                ipv4Address       = "198.51.100.24"
                ipv4Cidr          = "10.200.1.0/24"
                ipv6Full          = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
                ipv6Compressed    = "2001:db8::1"
                ipv4MappedIpv6    = "::ffff:192.0.2.128"
                compositeUri      = "https://graph.microsoft.com/v1.0/policies/12345678-1234-1234-1234-123456789abc/detail"
                nestedStructure   = [PSCustomObject]@{
                    deepLevel1 = [PSCustomObject]@{
                        deepUser = "director.audit@globalfin.org"
                        deepGuid = "fedcba98-7654-3210-fedc-ba9876543210"
                        deepIp   = "172.16.50.4"
                    }
                }
            }

            # Invoke the ACTUAL production ConvertTo-SanitizedJson function
            $json = ConvertTo-SanitizedJson -InputObject $sampleRawObject -TenantIdToRedact "11111111-2222-3333-4444-555555555555"

            # Assert no sensitive raw identifiers leaked
            ($json -match "11111111-2222-3333-4444-555555555555") | Should Be $false
            ($json -match "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d") | Should Be $false
            ($json -match "99999999-8888-7777-6666-555555555555") | Should Be $false
            ($json -match "88888888-7777-6666-5555-444444444444") | Should Be $false
            ($json -match "12345678-1234-1234-1234-123456789abc") | Should Be $false
            ($json -match "fedcba98-7654-3210-fedc-ba9876543210") | Should Be $false
            ($json -match "admin\.secops@mycorp\.onmicrosoft\.com") | Should Be $false
            ($json -match "contractor\.john@external-vendor\.com") | Should Be $false
            ($json -match "director\.audit@globalfin\.org") | Should Be $false
            ($json -match "198\.51\.100\.24") | Should Be $false
            ($json -match "10\.200\.1\.0/24") | Should Be $false
            ($json -match "172\.16\.50\.4") | Should Be $false
            ($json -match "2001:0db8:85a3") | Should Be $false
            ($json -match "2001:db8::1") | Should Be $false
            ($json -match "::ffff:192.0.2.128") | Should Be $false

            # Assert explicit replacement markers exist
            ($json -match "<REDACTED_TENANT_ID>") | Should Be $true
            ($json -match "<REDACTED_GUID>") | Should Be $true
            ($json -match "<REDACTED_USER>@<LAB_DOMAIN>") | Should Be $true
            ($json -match "<REDACTED_IP>") | Should Be $true
            ($json -match "<REDACTED_IPV6>") | Should Be $true
            ($json -match "<REDACTED_IPV4_MAPPED_IPV6>") | Should Be $true
        }
    }
}

