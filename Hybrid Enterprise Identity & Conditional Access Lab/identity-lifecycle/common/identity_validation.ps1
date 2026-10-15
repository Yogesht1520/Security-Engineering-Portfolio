<#
.SYNOPSIS
    Shared Identity Validation and RBAC Mapping Engine.
.DESCRIPTION
    Provides role-based group resolution, input validation, safeguard gates,
    and cryptographically secure credential generation for JML workflows.
#>

function New-SecureTemporaryPassword {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [int]$Length = 24
    )

    $upperChars   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lowerChars   = "abcdefghijkmnopqrstuvwxyz"
    $digitChars   = "23456789"
    $specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    $allChars = $upperChars + $lowerChars + $digitChars + $specialChars

    $bytes = New-Object byte[] ($Length)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)

    $chars = New-Object char[] ($Length)
    
    # Guarantee at least one from each character class for Entra ID complexity
    $chars[0] = $upperChars[$bytes[0] % $upperChars.Length]
    $chars[1] = $lowerChars[$bytes[1] % $lowerChars.Length]
    $chars[2] = $digitChars[$bytes[2] % $digitChars.Length]
    $chars[3] = $specialChars[$bytes[3] % $specialChars.Length]

    for ($i = 4; $i -lt $Length; $i++) {
        $chars[$i] = $allChars[$bytes[$i] % $allChars.Length]
    }

    # Fisher-Yates shuffle
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j = $bytes[$i] % ($i + 1)
        $temp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $temp
    }

    if ($PSCmdlet.ShouldProcess("TemporaryCredential", "Generate high-entropy random password")) {
        return New-Object string ($chars, 0, $Length)
    }
}

function Get-RbacGroupForDepartment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Department
    )

    switch -Regex ($Department.Trim()) {
        "^(Information Security|Cybersecurity|Identity & Access|IT Security|SecOps)$" {
            return "SEC-Admins"
        }
        "^(External Contractors|Contractor|Vendor|Consulting|Temporary Staff)$" {
            return "SEC-Contractors"
        }
        Default {
            return "SEC-StandardUsers"
        }
    }
}

function Assert-SafeIdentityTarget {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName
    )

    $protectedPrefixes = @("emergency-admin", "breakglass", "break-glass")
    foreach ($prefix in $protectedPrefixes) {
        if ($UserPrincipalName.ToLower().StartsWith($prefix)) {
            throw "CRITICAL SAFEGUARD TRIGGERED: Automated JML operations are prohibited on emergency break-glass account '$UserPrincipalName'."
        }
    }
}

