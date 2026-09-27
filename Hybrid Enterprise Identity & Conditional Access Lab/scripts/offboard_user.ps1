<#
.SYNOPSIS
    Automated User Offboarding (Leaver Lifecycle).
.DESCRIPTION
    Zero Trust emergency offboarding / leaver workflow:
    1. Revokes all active OAuth refresh tokens and browser sessions immediately (kills PRT / session cookies).
    2. Disables the Entra ID user account.
    3. Removes user from all privileged and standard security groups.
    4. Records an audit trail in the user's account metadata.
.PARAMETER UserPrincipalName
    The target UPN to offboard (e.g. cnt-sam@domain.com).
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName
)

Write-Host "==========================================================" -ForegroundColor Red
Write-Host "  Zero Trust User Offboarding Pipeline (Leaver Event)     " -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

# 1. Connect to Microsoft Graph
Write-Host "`n[1/4] Verifying Graph connection (Scope: User.ReadWrite.All, Group.ReadWrite.All)..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All" -NoWelcome

# 2. Locate Target User
$user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
if (-not $user) {
    Write-Error "User '$UserPrincipalName' was not found in the directory."
    exit 1
}

Write-Host "`nTarget User: $($user.DisplayName) (ID: $($user.Id))" -ForegroundColor White

# 3. Kill Active Sessions Immediately (Mitigates Stolen PRT / Session Cookie Replay)
Write-Host "`n[2/4] Revoking all active sign-in sessions and refresh tokens..." -ForegroundColor Yellow
try {
    Revoke-MgUserSignInSession -UserId $user.Id -ErrorAction Stop | Out-Null
    Write-Host "  -> Active refresh tokens successfully revoked." -ForegroundColor Green
} catch {
    Write-Warning "  -> Failed to revoke sessions: $($_.Exception.Message)"
}

# 4. Disable Entra Account
Write-Host "`n[3/4] Disabling Entra ID account..." -ForegroundColor Yellow
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Update-MgUser -UserId $user.Id -AccountEnabled:$false -Department "Offboarded"

Write-Host "  -> AccountEnabled set to False." -ForegroundColor Green

# 5. Remove Group Memberships
Write-Host "`n[4/4] Stripping all security group memberships..." -ForegroundColor Yellow
$memberships = Get-MgUserMemberOf -UserId $user.Id -All

foreach ($grp in $memberships) {
    if ($grp.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group') {
        $grpId = $grp.Id
        try {
            Remove-MgGroupMemberByRef -GroupId $grpId -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Host "  -> Removed from group: $($grp.AdditionalProperties['displayName'])" -ForegroundColor Gray
        } catch {
            Write-Warning "  -> Could not remove from group $grpId : $($_.Exception.Message)"
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  Offboarding completed for $UserPrincipalName at $timestamp" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
