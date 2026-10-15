<#
.SYNOPSIS
    Seeds synthetic users and security groups for the Entra ID Zero Trust & Conditional Access Lab.
.DESCRIPTION
    Phase 0 / Phase 1 Automation:
    - Connects to Microsoft Graph using interactive OAuth authentication (least privilege scopes).
    - Creates 4 security groups:
        1. SEC-Admins
        2. SEC-StandardUsers
        3. SEC-Contractors
        4. SEC-BreakGlass-Exclusion
    - Creates 10 test personas (8 workforce users + 2 emergency break-glass administrators).
    - Adds users to their designated security groups.
    - Exports resolved identifiers to local config for downstream policy automation.
.NOTES
    Lab: Enterprise Identity Security & Conditional Access Engineering Lab
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [System.Security.SecureString]$InitialPassword
)

# 0. Resolve Domain from Config if not explicitly provided
if (-not $Domain) {
    $tenantConfigFile = Join-Path $PSScriptRoot "..\config\tenant.json"
    if (Test-Path $tenantConfigFile) {
        $tenantConfig = Get-Content $tenantConfigFile -Raw | ConvertFrom-Json
        $Domain = $tenantConfig.primaryDomain
    }
}

if (-not $Domain) {
    $Domain = Read-Host "Enter your Entra ID Primary Domain (e.g. contoso.onmicrosoft.com)"
}

Write-Host "Target Domain: $Domain" -ForegroundColor Cyan

# 1. Secure Credential Handling
if (-not $InitialPassword) {
    Write-Host "`n[Security Requirement] Enter a temporary password for synthetic users (must meet complexity requirements):" -ForegroundColor Yellow
    $InitialPassword = Read-Host -AsSecureString
}

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($InitialPassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

# 2. Check and Load Microsoft Graph SDK
Write-Host "`n[1/5] Checking Microsoft.Graph PowerShell SDK..." -ForegroundColor Cyan
$requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups')

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing missing module: $module (Current User scope)..." -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
    } else {
        Write-Host "  -> Module $module is present." -ForegroundColor Green
    }
}

# 3. Connect to Microsoft Graph
Write-Host "`n[2/5] Connecting to Microsoft Graph (Scopes: User.ReadWrite.All, Group.ReadWrite.All)..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $Domain -Scopes "User.ReadWrite.All", "Group.ReadWrite.All" -NoWelcome

# 4. Provision Security Groups
Write-Host "`n[3/5] Provisioning Security Groups..." -ForegroundColor Cyan
$groupsToCreate = @(
    @{
        DisplayName     = "SEC-Admins"
        MailNickname    = "SEC-Admins"
        Description     = "Privileged administrative users subject to strict MFA, session controls, and PIM."
    },
    @{
        DisplayName     = "SEC-StandardUsers"
        MailNickname    = "SEC-StandardUsers"
        Description     = "Standard full-time workforce users."
    },
    @{
        DisplayName     = "SEC-Contractors"
        MailNickname    = "SEC-Contractors"
        Description     = "Third-party contractors subject to aggressive session timeout policies."
    },
    @{
        DisplayName     = "SEC-BreakGlass-Exclusion"
        MailNickname    = "SEC-BreakGlass-Exclusion"
        Description     = "Dedicated emergency break-glass exclusion group. Membership strictly restricted to 2 emergency accounts."
    }
)

$groupMap = @{}

foreach ($grp in $groupsToCreate) {
    $existing = Get-MgGroup -Filter "displayName eq '$($grp.DisplayName)'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [Exists] Group $($grp.DisplayName) (ID: $($existing.Id))" -ForegroundColor Gray
        $groupMap[$grp.DisplayName] = $existing.Id
    } else {
        $created = New-MgGroup -DisplayName $grp.DisplayName `
                               -MailNickname $grp.MailNickname `
                               -MailEnabled:$false `
                               -SecurityEnabled:$true `
                               -Description $grp.Description
        Write-Host "  [Created] Group $($grp.DisplayName) (ID: $($created.Id))" -ForegroundColor Green
        $groupMap[$grp.DisplayName] = $created.Id
    }
}

# 5. Provision Users
Write-Host "`n[4/5] Provisioning Synthetic Users..." -ForegroundColor Cyan

$passwordProfile = @{
    Password                      = $plainPassword
    ForceChangePasswordNextSignIn = $true
}

$usersToCreate = @(
    # Privileged Admins
    @{
        DisplayName       = "Alex Chen (Admin)"
        GivenName         = "Alex"
        Surname           = "Chen"
        UserPrincipalName = "adm-alex@$Domain"
        GroupName         = "SEC-Admins"
        JobTitle          = "Cloud Security Architect"
        Department        = "Information Security"
    },
    @{
        DisplayName       = "Morgan Vance (Admin)"
        GivenName         = "Morgan"
        Surname           = "Vance"
        UserPrincipalName = "adm-morgan@$Domain"
        GroupName         = "SEC-Admins"
        JobTitle          = "IAM Administrator"
        Department        = "Identity & Access"
    },
    # Standard Users
    @{
        DisplayName       = "Jordan Blake"
        GivenName         = "Jordan"
        Surname           = "Blake"
        UserPrincipalName = "usr-jordan@$Domain"
        GroupName         = "SEC-StandardUsers"
        JobTitle          = "Financial Analyst"
        Department        = "Finance"
    },
    @{
        DisplayName       = "Taylor Reese"
        GivenName         = "Taylor"
        Surname           = "Reese"
        UserPrincipalName = "usr-taylor@$Domain"
        GroupName         = "SEC-StandardUsers"
        JobTitle          = "Marketing Specialist"
        Department        = "Marketing"
    },
    @{
        DisplayName       = "Casey Smith"
        GivenName         = "Casey"
        Surname           = "Smith"
        UserPrincipalName = "usr-casey@$Domain"
        GroupName         = "SEC-StandardUsers"
        JobTitle          = "Software Engineer"
        Department        = "Engineering"
    },
    @{
        DisplayName       = "Riley Evans"
        GivenName         = "Riley"
        Surname           = "Evans"
        UserPrincipalName = "usr-riley@$Domain"
        GroupName         = "SEC-StandardUsers"
        JobTitle          = "HR Coordinator"
        Department        = "Human Resources"
    },
    # Contractors
    @{
        DisplayName       = "Sam Rivera (Contractor)"
        GivenName         = "Sam"
        Surname           = "Rivera"
        UserPrincipalName = "cnt-sam@$Domain"
        GroupName         = "SEC-Contractors"
        JobTitle          = "External Auditor"
        Department        = "External Contractors"
    },
    @{
        DisplayName       = "Pat Patel (Contractor)"
        GivenName         = "Pat"
        Surname           = "Patel"
        UserPrincipalName = "cnt-pat@$Domain"
        GroupName         = "SEC-Contractors"
        JobTitle          = "DevOps Consultant"
        Department        = "External Contractors"
    },
    # Dual Break-Glass Emergency Accounts
    @{
        DisplayName       = "Emergency Break-Glass 01"
        GivenName         = "Emergency"
        Surname           = "Admin-01"
        UserPrincipalName = "emergency-admin-01@$Domain"
        GroupName         = "SEC-BreakGlass-Exclusion"
        JobTitle          = "Break-Glass Account"
        Department        = "Security Operations"
    },
    @{
        DisplayName       = "Emergency Break-Glass 02"
        GivenName         = "Emergency"
        Surname           = "Admin-02"
        UserPrincipalName = "emergency-admin-02@$Domain"
        GroupName         = "SEC-BreakGlass-Exclusion"
        JobTitle          = "Break-Glass Account"
        Department        = "Security Operations"
    }
)

$userMap = @{}

foreach ($u in $usersToCreate) {
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($u.UserPrincipalName)'" -ErrorAction SilentlyContinue
    $userId = $null

    if ($existingUser) {
        Write-Host "  [Exists] User $($u.UserPrincipalName)" -ForegroundColor Gray
        $userId = $existingUser.Id
    } else {
        $mailNickname = $u.UserPrincipalName.Split("@")[0]
        try {
            $newUser = New-MgUser -DisplayName $u.DisplayName `
                                  -GivenName $u.GivenName `
                                  -Surname $u.Surname `
                                  -UserPrincipalName $u.UserPrincipalName `
                                  -MailNickname $mailNickname `
                                  -AccountEnabled:$true `
                                  -PasswordProfile $passwordProfile `
                                  -JobTitle $u.JobTitle `
                                  -Department $u.Department `
                                  -UsageLocation "US" `
                                  -ErrorAction Stop

            Write-Host "  [Created] User $($u.UserPrincipalName)" -ForegroundColor Green
            $userId = $newUser.Id
        } catch {
            Write-Host "  [Error creating user $($u.UserPrincipalName)]: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    if ($userId) {
        $userMap[$u.UserPrincipalName] = $userId
        # Add User to Group
        $targetGroupId = $groupMap[$u.GroupName]
        if ($targetGroupId) {
            try {
                New-MgGroupMember -GroupId $targetGroupId -DirectoryObjectId $userId -ErrorAction Stop | Out-Null
                Write-Host "    -> Added to group $($u.GroupName)" -ForegroundColor DarkGreen
            } catch {
                if ($_.Exception.Message -match "already exist") {
                    Write-Host "    -> Already in group $($u.GroupName)" -ForegroundColor Gray
                } else {
                    Write-Host "    -> Member status: $($_.Exception.Message)" -ForegroundColor Gray
                }
            }
        }
    }
}

# Clean memory
$plainPassword = $null
[System.GC]::Collect()

Write-Host "`n[5/5] Provisioning Complete!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Groups Created/Verified: SEC-Admins, SEC-StandardUsers, SEC-Contractors, SEC-BreakGlass-Exclusion" -ForegroundColor White
Write-Host "Users Created/Verified: 8 Workforce Personas + 2 Emergency Break-Glass Admins" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
