<#
.SYNOPSIS
    Privileged Group Membership Audit and Attestation Engine for Microsoft Entra ID.
.DESCRIPTION
    Custom PowerShell Entitlement Attestation Engine for Tier-0 and Tier-1 security groups:
    - Identifies as Privileged Group Membership Audit and Attestation Engine.
    - Resolves and verifies target privileged security groups, rejecting duplicate group names.
    - Inspects membership types: detects nested groups, dynamic groups, service principals, and users.
    - Flags disabled accounts retaining active group memberships or privileged paths.
    - Detects stale accounts with no interactive sign-in activity in the last 90 days.
    - Identifies external guest accounts possessing administrative or internal group access.
    - Verifies emergency break-glass account isolation and group membership purity.
    - Documents exact audit scope, evaluated groups, dynamic rules, and excluded objects.
    - Note on Entra Native Access Reviews: This engine performs programmatic membership auditing
      and attestation. For Microsoft native Access Reviews (with recurring portal campaigns,
      self-attestation, and automated revocation), see docs/IDENTITY_GOVERNANCE.md.
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
Write-Host "  Privileged Group Membership Audit & Attestation Engine  " -ForegroundColor Cyan
Write-Host "  Zero Trust Tier-0/Tier-1 Security Group Audit Subsystem" -ForegroundColor Cyan
Write-Host "  (Custom Engine - Native Entra Access Reviews ref: docs/IDENTITY_GOVERNANCE.md)" -ForegroundColor DarkGray
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
Write-Host "`n[Step 1/3] Querying privileged groups and members (with pagination)..." -ForegroundColor Cyan

$reviewResults = [System.Collections.Generic.List[psobject]]::new()
$auditedGroups = [System.Collections.Generic.List[psobject]]::new()
$dynamicGroupsDetected = [System.Collections.Generic.List[psobject]]::new()
$excludedObjects = [System.Collections.Generic.List[psobject]]::new()
$nowUtc = (Get-Date).ToUniversalTime()
$inactiveThreshold = $nowUtc.AddDays(-$MaxInactiveDays)

foreach ($grpName in $GroupNames) {
    Write-Host "  Auditing group: $grpName..." -ForegroundColor Yellow
    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$grpName'"
    $groupResp = Invoke-MgGraphRequest -Method GET -Uri $groupUri

    if (-not $groupResp.value -or @($groupResp.value).Count -eq 0) {
        Write-Host "    [WARNING] Group '$grpName' not found in tenant." -ForegroundColor Yellow
        $excludedObjects.Add([PSCustomObject]@{
            ObjectType = "Group"
            Identifier = $grpName
            Reason     = "GroupNotFound"
        })
        continue
    }

    # Finding 7: Check for duplicate group names in tenant
    if (@($groupResp.value).Count -gt 1) {
        Write-Error "    [DUPLICATE GROUP AMBIGUITY] Multiple groups ($(@($groupResp.value).Count)) share display name '$grpName'!"
        $excludedObjects.Add([PSCustomObject]@{
            ObjectType = "Group"
            Identifier = $grpName
            Reason     = "DuplicateGroupDisplayNameAmbiguity"
            Count      = @($groupResp.value).Count
        })
        $reviewResults.Add([PSCustomObject]@{
            GroupName          = $grpName
            GroupId            = "AMBIGUOUS"
            PrincipalType      = "Group"
            UserId             = $null
            DisplayName        = "[DuplicateGroupAmbiguity]"
            UserPrincipalName  = "[DuplicateGroupAmbiguity]"
            AccountEnabled     = $null
            UserType           = $null
            LastSignInDateTime = $null
            ReviewStatus       = "Incomplete"
            ComplianceFlags    = "DUPLICATE_GROUP_NAME"
            Recommendation     = "Investigate and resolve ambiguous duplicate group names"
            AttestedAtUtc      = $nowUtc.ToString("o")
        })
        continue
    }

    $targetGrp = $groupResp.value[0]
    $groupId = $targetGrp.id

    # Finding 7: Dynamic group limitations check
    $isDynamic = ($targetGrp.groupTypes -and $targetGrp.groupTypes -contains "DynamicMembership")
    if ($isDynamic) {
        Write-Warning "    [DYNAMIC GROUP] '$grpName' is a Dynamic Membership group. Direct member removal is not supported; membership is rule-driven."
        $dynamicGroupsDetected.Add([PSCustomObject]@{
            GroupId     = $groupId
            DisplayName = $grpName
            MembershipRule = $targetGrp.membershipRule
        })
    }

    $auditedGroups.Add([PSCustomObject]@{
        GroupId           = $groupId
        DisplayName       = $grpName
        IsDynamic         = $isDynamic
        SecurityEnabled   = $targetGrp.securityEnabled
    })

    $membersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,displayName,userPrincipalName,accountEnabled,userType,signInActivity,appId"
    $allGroupMembers = [System.Collections.Generic.List[PSObject]]::new()
    $groupQueryFailed = $false

    try {
        while ($membersUri) {
            $membersResp = Invoke-MgGraphRequest -Method GET -Uri $membersUri -ErrorAction Stop
            if ($membersResp.value) {
                foreach ($m in $membersResp.value) {
                    $allGroupMembers.Add($m)
                }
            }
            $membersUri = $membersResp.'@odata.nextLink'
        }
    } catch {
        $groupQueryFailed = $true
        Write-Warning "    [INCOMPLETE REVIEW] Failed querying members for group '$grpName': $($_.Exception.Message)"
        $reviewResults.Add([PSCustomObject]@{
            GroupName          = $grpName
            GroupId            = $groupId
            PrincipalType      = "Unknown"
            UserId             = $null
            DisplayName        = "[QueryFailed]"
            UserPrincipalName  = "[QueryFailed]"
            AccountEnabled     = $null
            UserType           = $null
            LastSignInDateTime = $null
            ReviewStatus       = "Incomplete"
            ComplianceFlags    = "QUERY_FAILED"
            Recommendation     = "Re-run review with verified Directory.Read.All permissions"
            AttestedAtUtc      = $nowUtc.ToString("o")
        })
    }

    if ($groupQueryFailed) {
        continue
    }

    Write-Host "    -> Found $($allGroupMembers.Count) member(s)." -ForegroundColor Gray

    foreach ($member in $allGroupMembers) {
        $userId = $member.id
        $upn = $member.userPrincipalName
        $displayName = $member.displayName
        $isEnabled = [bool]$member.accountEnabled
        $userType = $member.userType
        $odataType = if ($member.'@odata.type') { $member.'@odata.type' } else { "#microsoft.graph.user" }

        # Finding 7: Detect non-user principals and nested groups
        $principalType = "User"
        $flags = [System.Collections.Generic.List[string]]::new()
        $recommendation = "Maintain"

        if ($odataType -match "servicePrincipal") {
            $principalType = "ServicePrincipal"
            $upn = if ($member.appId) { "AppId: $($member.appId)" } else { "ServicePrincipal" }
            $flags.Add("SERVICE_PRINCIPAL_IN_PRIVILEGED_GROUP")
            $recommendation = "Audit service principal workload identity access & app role assignments"
        } elseif ($odataType -match "group") {
            $principalType = "NestedGroup"
            $upn = "NestedGroupId: $userId"
            $flags.Add("NESTED_GROUP_IN_PRIVILEGED_GROUP")
            $recommendation = "Review nested group access: Zero Trust architecture mandates flat privileged role assignment"
        } elseif ($odataType -match "device") {
            $principalType = "Device"
            $upn = "DeviceId: $userId"
            $flags.Add("DEVICE_IN_PRIVILEGED_GROUP")
            $recommendation = "Remove device object from privileged user group"
        } else {
            # User principal evaluation
            $lastSignIn = "Never"
            $isInactive = $false
            if ($member.signInActivity -and $member.signInActivity.lastSignInDateTime) {
                $lastSignInDate = [datetime]$member.signInActivity.lastSignInDateTime
                $lastSignIn = $lastSignInDate.ToString("yyyy-MM-dd HH:mm:ss UTC")
                if ($lastSignInDate -lt $inactiveThreshold) {
                    $isInactive = $true
                }
            }

            # Flag 1: Disabled account with active membership
            if (-not $isEnabled) {
                $flags.Add("DISABLED_ACCOUNT")
                $recommendation = "Revoke access immediately (disabled account retains group membership)"
            }

            # Flag 2: Guest user in internal privileged group
            if ($userType -eq "Guest") {
                $flags.Add("GUEST_IN_PRIVILEGED_GROUP")
                $recommendation = "Review business justification for external guest privileges"
            }

            # Flag 3: Stale account
            if ($isInactive) {
                $flags.Add("STALE_ACCOUNT_OVER_90D")
                $recommendation = "Revoke access or re-attest business need due to >90d inactivity"
            }

            # Flag 4: Break-glass isolation check
            if ($grpName -eq "SEC-BreakGlass-Exclusion") {
                if ($upn -notlike "emergency-admin*") {
                    $flags.Add("UNAUTHORIZED_BREAKGLASS_MEMBER")
                    $recommendation = "CRITICAL: Non-breakglass account in emergency exclusion group! Immediate removal required."
                }
            }
        }

        $findingStatus = if ($flags.Count -gt 0) { "Attention Required" } else { "Approved" }

        $record = [PSCustomObject]@{
            GroupName          = $grpName
            GroupId            = $groupId
            PrincipalType      = $principalType
            UserId             = $userId
            DisplayName        = $displayName
            UserPrincipalName  = $upn
            AccountEnabled     = $isEnabled
            UserType           = $userType
            LastSignInDateTime = (if ($principalType -eq "User") { $lastSignIn } else { "N/A ($principalType)" })
            ReviewStatus       = $findingStatus
            ComplianceFlags    = ($flags -join "; ")
            Recommendation     = $recommendation
            AttestedAtUtc      = $nowUtc.ToString("o")
        }

        $reviewResults.Add($record)
    }
}

# 3. Summary & Findings
Write-Host "`n[Step 2/3] Access Review Summary:" -ForegroundColor Cyan
$flagged = @($reviewResults | Where-Object { $_.ReviewStatus -eq "Attention Required" })
Write-Host "Total Identities Reviewed: $($reviewResults.Count)" -ForegroundColor White
Write-Host "Identities Approved      : $(($reviewResults.Count) - ($flagged.Count))" -ForegroundColor Green
Write-Host "Identities Requiring Action: $($flagged.Count)" -ForegroundColor $(if($flagged.Count -gt 0){"Red"}else{"Green"})

if ($flagged.Count -gt 0) {
    Write-Host "`n[ACTION ITEMS IDENTIFIED]:" -ForegroundColor Red
    $flagged | Format-Table DisplayName, GroupName, PrincipalType, ComplianceFlags, Recommendation -AutoSize
}

# 4. Export Evidence
Write-Host "`n[Step 3/3] Exporting Access Review Attestation Evidence..." -ForegroundColor Cyan
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonPath = Join-Path $OutputPath "access_review_attestation_$timestamp.json"
$csvPath = Join-Path $OutputPath "access_review_attestation_$timestamp.csv"

$incompleteCount = @($reviewResults | Where-Object { $_.ReviewStatus -eq "Incomplete" }).Count
$overallStatus = if ($incompleteCount -gt 0) { "Incomplete" } elseif ($flagged.Count -gt 0) { "ActionRequired" } else { "Approved" }

$attestationEnvelope = [PSCustomObject]@{
    EngineTitle          = "Privileged Group Membership Audit and Attestation Engine"
    TenantId             = $activeContext.TenantId
    AttestationTimestamp = $nowUtc.ToString("o")
    Reviewer             = $activeContext.Account
    OverallStatus        = $overallStatus
    AuditScope           = [PSCustomObject]@{
        TargetGroupsRequested = $GroupNames
        GroupsAudited         = $auditedGroups
        DynamicGroupsDetected = $dynamicGroupsDetected
        ExcludedObjects       = $excludedObjects
        MaxInactiveDays       = $MaxInactiveDays
    }
    TotalReviewed        = $reviewResults.Count
    FlaggedCount         = $flagged.Count
    IncompleteCount      = $incompleteCount
    AuditRecords         = $reviewResults
}

$attestationEnvelope | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8
$reviewResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

Write-Host "  -> JSON Attestation Evidence: $jsonPath" -ForegroundColor Gray
Write-Host "  -> CSV Audit Spreadsheet   : $csvPath" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan
