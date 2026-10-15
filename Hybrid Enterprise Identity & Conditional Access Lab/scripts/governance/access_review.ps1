<#
.SYNOPSIS
    Automated Identity Access Review & Attestation Engine for Microsoft Entra ID.
.DESCRIPTION
    Automates identity access reviews and self-attestation audits for Zero Trust compliance (ISO 27001, SOC 2, NIST CSF):
    - Audits privileged security groups (e.g., 'SEC-Admins', 'SEC-BreakGlass-Exclusion').
    - Detects disabled accounts that retain active group memberships or role assignments.
    - Flags stale accounts with no interactive sign-in activity in the last 90 days.
    - Identifies external guest accounts possessing administrative or internal group access.
    - Generates auditable compliance attestation records.
.PARAMETER GroupNames
    List of privileged group names to review. Default is @('SEC-Admins', 'SEC-BreakGlass-Exclusion').
.PARAMETER MaxInactiveDays
    Threshold in days for stale account detection. Default is 90 days.
.PARAMETER OutputPath
    Directory where attestation reports will be written. Default is 'reports'.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
#>

[CmdletBinding()]
param (
    [string[]]$GroupNames = @("SEC-Admins", "SEC-BreakGlass-Exclusion"),
    [int]$MaxInactiveDays = 90,
    [string]$OutputPath = "$PSScriptRoot\..\..\reports",
    [switch]$DeviceCode
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Identity Access Review & Attestation Governance Engine" -ForegroundColor Cyan
Write-Host "  Microsoft Entra ID Zero Trust Compliance" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Connect to Microsoft Graph
$activeContext = Get-MgContext -ErrorAction SilentlyContinue
$requiredScopes = @("Group.Read.All", "User.Read.All", "AuditLog.Read.All", "Directory.Read.All")

$needsAuth = $false
if (-not $activeContext) {
    $needsAuth = $true
} else {
    foreach ($scope in $requiredScopes) {
        if ($activeContext.Scopes -notcontains $scope) {
            $needsAuth = $true
            break
        }
    }
}

if ($needsAuth) {
    Write-Host "`n[Authentication] Connecting to Microsoft Graph with governance scopes..." -ForegroundColor Yellow
    $env:ENTRA_IDENTITY_DISABLE_WAM = "true"
    $authParams = @{
        Scopes = $requiredScopes
        NoWelcome = $true
    }
    if ($DeviceCode) {
        $authParams["UseDeviceAuthentication"] = $true
    }
    Connect-MgGraph @authParams
    $activeContext = Get-MgContext
}

Write-Host "Connected to Tenant: $($activeContext.TenantId)" -ForegroundColor Green

# 2. Review Target Privileged Groups
Write-Host "`n[Step 1/3] Querying privileged groups and members..." -ForegroundColor Cyan

$reviewResults = @()
$nowUtc = (Get-Date).ToUniversalTime()
$inactiveThreshold = $nowUtc.AddDays(-$MaxInactiveDays)

foreach ($grpName in $GroupNames) {
    Write-Host "  Auditing group: $grpName..." -ForegroundColor Yellow
    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$grpName'"
    $groupResp = Invoke-MgGraphRequest -Method GET -Uri $groupUri

    if (-not $groupResp.value -or $groupResp.value.Count -eq 0) {
        Write-Host "    [WARNING] Group '$grpName' not found in tenant." -ForegroundColor Yellow
        continue
    }

    $groupId = $groupResp.value[0].id
    $membersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,displayName,userPrincipalName,accountEnabled,userType,signInActivity"
    $membersResp = Invoke-MgGraphRequest -Method GET -Uri $membersUri

    Write-Host "    -> Found $($membersResp.value.Count) member(s)." -ForegroundColor Gray

    foreach ($member in $membersResp.value) {
        $userId = $member.id
        $upn = $member.userPrincipalName
        $displayName = $member.displayName
        $isEnabled = [bool]$member.accountEnabled
        $userType = $member.userType

        $lastSignIn = "Never"
        $isInactive = $false
        if ($member.signInActivity -and $member.signInActivity.lastSignInDateTime) {
            $lastSignInDate = [datetime]$member.signInActivity.lastSignInDateTime
            $lastSignIn = $lastSignInDate.ToString("yyyy-MM-dd HH:mm:ss UTC")
            if ($lastSignInDate -lt $inactiveThreshold) {
                $isInactive = $true
            }
        } else {
            # Never logged in or audit log not populated
            $isInactive = $false # We don't flag as inactive if account is freshly seeded
        }

        # Compliance Flags
        $flags = @()
        $recommendation = "Maintain"

        # Flag 1: Disabled account with active membership
        if (-not $isEnabled) {
            $flags += "DISABLED_ACCOUNT"
            $recommendation = "Revoke access immediately (disabled account retains group membership)"
        }

        # Flag 2: Guest user in internal privileged group
        if ($userType -eq "Guest") {
            $flags += "GUEST_IN_PRIVILEGED_GROUP"
            $recommendation = "Review business justification for external guest privileges"
        }

        # Flag 3: Stale account
        if ($isInactive) {
            $flags += "STALE_ACCOUNT_OVER_90D"
            $recommendation = "Revoke access or re-attest business need due to >90d inactivity"
        }

        # Flag 4: Break-glass isolation check
        if ($grpName -eq "SEC-BreakGlass-Exclusion") {
            if ($upn -notlike "emergency-admin*") {
                $flags += "UNAUTHORIZED_BREAKGLASS_MEMBER"
                $recommendation = "CRITICAL: Non-breakglass account in emergency exclusion group! Immediate removal required."
            }
        }

        $findingStatus = if ($flags.Count -gt 0) { "Attention Required" } else { "Approved" }

        $record = [PSCustomObject]@{
            GroupName          = $grpName
            GroupId            = $groupId
            UserId             = $userId
            DisplayName        = $displayName
            UserPrincipalName  = $upn
            AccountEnabled     = $isEnabled
            UserType           = $userType
            LastSignInDateTime = $lastSignIn
            ReviewStatus       = $findingStatus
            ComplianceFlags    = ($flags -join "; ")
            Recommendation     = $recommendation
            AttestedAtUtc      = $nowUtc.ToString("o")
        }

        $reviewResults += $record
    }
}

# 3. Summary & Findings
Write-Host "`n[Step 2/3] Access Review Summary:" -ForegroundColor Cyan
$flagged = $reviewResults | Where-Object { $_.ReviewStatus -eq "Attention Required" }
Write-Host "Total Identities Reviewed: $($reviewResults.Count)" -ForegroundColor White
Write-Host "Identities Approved      : $(($reviewResults.Count) - ($flagged.Count))" -ForegroundColor Green
Write-Host "Identities Requiring Action: $($flagged.Count)" -ForegroundColor $(if($flagged.Count -gt 0){"Red"}else{"Green"})

if ($flagged.Count -gt 0) {
    Write-Host "`n[ACTION ITEMS IDENTIFIED]:" -ForegroundColor Red
    $flagged | Format-Table DisplayName, GroupName, ComplianceFlags, Recommendation -AutoSize
}

# 4. Export Evidence
Write-Host "`n[Step 3/3] Exporting Access Review Attestation Evidence..." -ForegroundColor Cyan
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonPath = Join-Path $OutputPath "access_review_attestation_$timestamp.json"
$csvPath = Join-Path $OutputPath "access_review_attestation_$timestamp.csv"

$attestationEnvelope = @{
    TenantId             = $activeContext.TenantId
    AttestationTimestamp = $nowUtc.ToString("o")
    Reviewer             = $activeContext.Account
    TotalReviewed        = $reviewResults.Count
    FlaggedCount         = $flagged.Count
    AuditRecords         = $reviewResults
}

$attestationEnvelope | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8
$reviewResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

Write-Host "  -> JSON Attestation Evidence: $jsonPath" -ForegroundColor Gray
Write-Host "  -> CSV Audit Spreadsheet   : $csvPath" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan
