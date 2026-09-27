<#
.SYNOPSIS
    Seeds synthetic users and security groups for the Entra ID Hybrid & Conditional Access Lab.
.DESCRIPTION
    Automates Phase 1:
    - Connects to Microsoft Graph using interactive OAuth authentication.
    - Creates 3 security groups: SEC-Admins, SEC-StandardUsers, SEC-Contractors.
    - Creates 8 test users across departments with standardized naming conventions.
    - Adds test users to their respective security groups.
.NOTES
    Lab: Hybrid Enterprise Identity & Conditional Access Lab
    Domain: quickheal327.onmicrosoft.com
#>

param (
    [string]$Domain = "quickheal327.onmicrosoft.com",
    [string]$DefaultPassword = "LabSecurePassword2026!"
)

# 1. Verify and Install Microsoft Graph SDK if missing
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

# 2. Connect to Microsoft Graph
Write-Host "`n[2/5] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "Please sign in with your Lab Admin account: YogeshThakur@$Domain" -ForegroundColor Yellow
Write-Host "IMPORTANT: Do NOT select your corporate @quickheal.com account!" -ForegroundColor Magenta
Write-Host "Check 'Consent on behalf of your organization' if prompted." -ForegroundColor Magenta
Connect-MgGraph -TenantId "464a788a-fba5-4e94-9b06-a6359091ad74" -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All" -NoWelcome

# 3. Create Security Groups
Write-Host "`n[3/5] Provisioning Security Groups..." -ForegroundColor Cyan
$groupsToCreate = @(
    @{
        DisplayName     = "SEC-Admins"
        MailNickname    = "SEC-Admins"
        Description     = "Privileged administrative users subject to strict MFA and session controls."
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
    }
)

$groupMap = @{}

foreach ($grp in $groupsToCreate) {
    $existing = Get-MgGroup -Filter "displayName eq '$($grp.DisplayName)'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [Exists] Group $($grp.DisplayName) already exists (ID: $($existing.Id))" -ForegroundColor Gray
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

# 4. Create Synthetic Test Users
Write-Host "`n[4/5] Provisioning Synthetic Users..." -ForegroundColor Cyan

$passwordProfile = @{
    Password                      = $DefaultPassword
    ForceChangePasswordNextSignIn = $false
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
    }
)

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

    # 5. Add User to Group
    $targetGroupId = $groupMap[$u.GroupName]
    if ($targetGroupId -and $userId) {
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

Write-Host "`n[5/5] Seeding Complete!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Default password for all test accounts: $DefaultPassword" -ForegroundColor Yellow
Write-Host "Groups created: SEC-Admins, SEC-StandardUsers, SEC-Contractors" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
