<#
.SYNOPSIS
    Pester Test Suite: Identity Lifecycle (Joiner-Mover-Leaver) Engine.
#>

Describe "Identity Lifecycle Engine & RBAC Validation" {
    $lifecycleDir = Join-Path $PSScriptRoot "..\identity-lifecycle"
    . (Join-Path $lifecycleDir "common\identity_validation.ps1")

    Context "Cryptographic Credential Generation" {
        It "Generates 24-character high-entropy temporary passwords meeting complexity rules" {
            $pass = New-SecureTemporaryPassword -Length 24
            $pass.Length | Should Be 24
            ($pass -cmatch "[A-Z]") | Should Be $true
            ($pass -cmatch "[a-z]") | Should Be $true
            ($pass -match "[0-9]")   | Should Be $true
            ($pass -match "[^a-zA-Z0-9]") | Should Be $true
        }
    }

    Context "RBAC Department Mapping" {
        It "Maps Information Security to SEC-Admins" {
            (Get-RbacGroupForDepartment -Department "Information Security") | Should Be "SEC-Admins"
        }

        It "Maps External Contractors to SEC-Contractors" {
            (Get-RbacGroupForDepartment -Department "External Contractors") | Should Be "SEC-Contractors"
        }

        It "Maps standard departments to SEC-StandardUsers" {
            (Get-RbacGroupForDepartment -Department "Finance") | Should Be "SEC-StandardUsers"
            (Get-RbacGroupForDepartment -Department "Marketing") | Should Be "SEC-StandardUsers"
            (Get-RbacGroupForDepartment -Department "Engineering") | Should Be "SEC-StandardUsers"
        }
    }

    Context "Fail-Closed Safeguard Assertions" {
        It "Must throw terminating error when attempting lifecycle actions on emergency break-glass account" {
            { Assert-SafeIdentityTarget -UserPrincipalName "emergency-admin-01@domain.com" } | Should Throw
            { Assert-SafeIdentityTarget -UserPrincipalName "breakglass@domain.com" } | Should Throw
        }

        It "Allows actions on standard workforce identities" {
            { Assert-SafeIdentityTarget -UserPrincipalName "usr-jane@domain.com" } | Should Not Throw
            { Assert-SafeIdentityTarget -UserPrincipalName "adm-alex@domain.com" } | Should Not Throw
        }
    }
}
