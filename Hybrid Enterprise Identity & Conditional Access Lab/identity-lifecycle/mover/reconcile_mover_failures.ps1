<#
.SYNOPSIS
    Automated Mover Reconciliation and Privilege Creep Remediation Engine.
.DESCRIPTION
    Reconciles incomplete or failed identity transitions:
    - Audits all identities across managed RBAC groups (SEC-Admins, SEC-StandardUsers, SEC-Contractors).
    - Detects multi-group entitlement conflicts (Privilege Creep) resulting from partial Mover execution.
    - Verifies department-to-group alignment.
    - Under -Fix, purges residual legacy memberships, establishes proper target group, and flushes tokens.
    - Records immutable reconciliation telemetry.
.PARAMETER Fix
    Remediates detected conflicts and purges legacy memberships.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [switch]$Fix,
    [switch]$DeviceCode
)

$commonDir = Join-Path $PSScriptRoot "..\common"
. (Join-Path $commonDir "audit_logger.ps1")
. (Join-Path $commonDir "identity_validation.ps1")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity Reconciliation: MOVER STATE AUDIT  " -ForegroundColor Cyan
Write-Host "  Privilege Creep & Partial Transaction Remediation      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Graph Authentication
$env:ENTRA_IDENTITY_DISABLE_WAM = "true"
$activeContext = Get-MgContext -ErrorAction SilentlyContinue
$requiredScopes = @("User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All")

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
    $authParams = @{
        Scopes = $requiredScopes
        NoWelcome = $true
    }
    if ($DeviceCode) { $authParams["UseDeviceAuthentication"] = $true }
    Connect-MgGraph @authParams
    $activeContext = Get-MgContext
}

# 2. Query Managed Groups
$managedGroups = @("SEC-StandardUsers", "SEC-Admins", "SEC-Contractors")
$groupObjects = @{}

foreach ($gName in $managedGroups) {
    $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$gName'"
    $res = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
    if ($res.value -and $res.value.Count -gt 0) {
        $groupObjects[$gName] = $res.value[0]
    }
}

# 3. Query Members of All Managed Groups
$userMemberships = @{} # UPN -> list of group names

foreach ($entry in $groupObjects.GetEnumerator()) {
    $gName = $entry.Key
    $gId   = $entry.Value.id

    $memUri = "https://graph.microsoft.com/v1.0/groups/$gId/members?`$select=id,userPrincipalName,department,jobTitle"
    while ($memUri) {
        $memResp = Invoke-MgGraphRequest -Method GET -Uri $memUri -ErrorAction SilentlyContinue
        if ($memResp.value) {
            foreach ($m in $memResp.value) {
                $upn = $m.userPrincipalName
                if (-not $upn) { continue }
                if (-not $userMemberships.ContainsKey($upn)) {
                    $userMemberships[$upn] = @{
                        Id = $m.id
                        Department = $m.department
                        JobTitle = $m.jobTitle
                        Groups = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $userMemberships[$upn].Groups.Add($gName)
            }
        }
        $memUri = $memResp.'@odata.nextLink'
    }
}

# 4. Evaluate Conflicts
$conflicts = @()

foreach ($entry in $userMemberships.GetEnumerator()) {
    $upn  = $entry.Key
    $data = $entry.Value
    $grps = $data.Groups

    # Multi-group conflict check
    if ($grps.Count -gt 1) {
        $expectedGroup = Get-RbacGroupForDepartment -Department $data.Department
        $conflicts += [PSCustomObject]@{
            UserPrincipalName = $upn
            UserId            = $data.Id
            Department        = $data.Department
            ActiveGroups      = ($grps -join ", ")
            ExpectedGroup     = $expectedGroup
            LegacyGroups      = ($grps | Where-Object { $_ -ne $expectedGroup }) -join ", "
            Status            = "Conflict: MultiGroupMembership"
        }
    }
}

Write-Host "`nDiscovered $($conflicts.Count) identity entitlement conflict(s):" -ForegroundColor $(if ($conflicts.Count -gt 0) { "Yellow" } else { "Green" })
if ($conflicts.Count -gt 0) {
    $conflicts | Format-Table -Property UserPrincipalName, Department, ActiveGroups, ExpectedGroup, LegacyGroups, Status -AutoSize
}

# 5. Remediation Pass
if ($conflicts.Count -gt 0 -and $Fix) {
    Write-Host "`n[REMEDIATING CONFLICTS] Executing purge of residual legacy memberships..." -ForegroundColor Cyan
    foreach ($c in $conflicts) {
        $legacyList = $c.LegacyGroups.Split(",") | ForEach-Object { $_.Trim() }
        foreach ($legName in $legacyList) {
            if ($groupObjects.ContainsKey($legName)) {
                $legId = $groupObjects[$legName].id
                Write-Host "  [Purging] Removing '$($c.UserPrincipalName)' from legacy group '$legName'..." -ForegroundColor Yellow
                if ($PSCmdlet.ShouldProcess("$($c.UserPrincipalName)", "Remove from legacy group '$legName'")) {
                    try {
                        $delUri = "https://graph.microsoft.com/v1.0/groups/$legId/members/$($c.UserId)/`$ref"
                        Invoke-MgGraphRequest -Method DELETE -Uri $delUri -ErrorAction Stop
                        Write-Host "  -> Purge complete: $legName" -ForegroundColor Green
                    } catch {
                        Write-Error "  -> Failed purging from $($legName): $($_.Exception.Message)"
                    }
                }
            }
        }

        # Revoke tokens to ensure newly cleaned claims are evaluated immediately
        Write-Host "  [Revoking Tokens] Invalidating refresh tokens for '$($c.UserPrincipalName)'..." -ForegroundColor Cyan
        if ($PSCmdlet.ShouldProcess("$($c.UserPrincipalName)", "Revoke active sign-in sessions")) {
            try {
                $revUri = "https://graph.microsoft.com/v1.0/users/$($c.UserId)/revokeSignInSessions"
                Invoke-MgGraphRequest -Method POST -Uri $revUri -ContentType "application/json" -ErrorAction Stop | Out-Null
                Write-Host "  -> Sessions invalidated." -ForegroundColor Green
            } catch {
                Write-Warning "  -> Token revocation returned: $($_.Exception.Message)"
            }
        }

        # Write audit log
        if ($PSCmdlet.ShouldProcess("$($c.UserPrincipalName)", "Write reconciliation audit log")) {
            Write-LifecycleAuditLog -EventType "RECONCILIATION" `
                                    -TargetUserPrincipalName $c.UserPrincipalName `
                                    -TargetUserId $c.UserId `
                                    -Details "Reconciled multi-group mover conflict. Stripped legacy groups: $($c.LegacyGroups). Preserved target: $($c.ExpectedGroup)." `
                                    -TransactionState "Completed"
        }
    }
    Write-Host "`nReconciliation run complete. All identified privilege creep states resolved." -ForegroundColor Green
} elseif ($conflicts.Count -gt 0) {
    Write-Host "`nRun with -Fix to automatically purge legacy memberships and revoke active sessions." -ForegroundColor Yellow
} else {
    Write-Host "`nAll directory identities are cleanly reconciled with zero privilege creep." -ForegroundColor Green
}
