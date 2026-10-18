<#
.SYNOPSIS
    Enterprise Joiner Automation Engine (Onboarding Workflow).
.DESCRIPTION
    Automates secure employee and contractor onboarding in Microsoft Entra ID:
    - Generates high-entropy cryptographically secure temporary passwords.
    - Enforces mandatory password change on first sign-in.
    - Dynamically evaluates Role-Based Access Control (RBAC) security group mapping.
    - Configures usage location, job title, and department metadata.
    - Writes structured, compliance-ready audit telemetry.
.PARAMETER GivenName
    User's first name.
.PARAMETER Surname
    User's last name.
.PARAMETER UserPrincipalName
    Target User Principal Name (e.g. usr-jane@domain.onmicrosoft.com).
.PARAMETER Department
    Business unit/department (e.g. Finance, Marketing, Information Security, External Contractors).
.PARAMETER JobTitle
    Corporate job title.
.PARAMETER UsageLocation
    ISO 2-letter country code for Microsoft 365 licensing eligibility. Default is 'US'.
.PARAMETER GroupNameOverride
    Optional manual override for assigned security group.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
.PARAMETER WhatIf
    Performs a dry run without modifying tenant state.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [string]$GivenName,

    [Parameter(Mandatory=$true)]
    [string]$Surname,

    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory=$true)]
    [string]$Department,

    [Parameter(Mandatory=$true)]
    [string]$JobTitle,

    [string]$UsageLocation = "US",

    [string]$GroupNameOverride,

    [switch]$DeviceCode
)

# Load Shared Modules
$commonDir = Join-Path $PSScriptRoot "..\common"
. (Join-Path $commonDir "audit_logger.ps1")
. (Join-Path $commonDir "identity_validation.ps1")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity Lifecycle Engine: JOINER Workflow   " -ForegroundColor Cyan
Write-Host "  Zero Trust Automated Identity Provisioning              " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Pre-Flight Validation & Safeguards
try {
    Assert-SafeIdentityTarget -UserPrincipalName $UserPrincipalName
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

$displayName = "$GivenName $Surname"
$mailNickname = $UserPrincipalName.Split("@")[0]
$assignedGroup = if ($GroupNameOverride) { $GroupNameOverride } else { Get-RbacGroupForDepartment -Department $Department }

Write-Host "`n[Candidate Metadata]:" -ForegroundColor White
Write-Host "  Name              : $displayName"
Write-Host "  UPN               : $UserPrincipalName"
Write-Host "  Department        : $Department"
Write-Host "  Job Title         : $JobTitle"
Write-Host "  Target RBAC Group : $assignedGroup"

if ($WhatIfPreference) {
    Write-Host "`n[WhatIf] Dry-run enabled. Would provision $UserPrincipalName and assign to $assignedGroup." -ForegroundColor Yellow
    exit 0
}

# 2. Graph Authentication
$env:ENTRA_IDENTITY_DISABLE_WAM = "true"
$activeContext = $null
try {
    $activeContext = Get-MgContext -ErrorAction Stop
} catch {
    $activeContext = $null
}

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
    Write-Host "`n[Authentication] Connecting to Microsoft Graph..." -ForegroundColor Yellow
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

# 3. Check for Duplicate UPN (Finding 9: Fail-closed, distinguish 404 from directory failures)
Write-Host "`n[Step 1/3] Checking for duplicate user in directory..." -ForegroundColor Cyan
try {
    $existence = Test-UserPrincipalNameExistence -UserPrincipalName $UserPrincipalName
    if ($existence.Exists) {
        Write-Error "Identity with UPN '$UserPrincipalName' already exists in tenant (ID: $($existence.User.id))."
        try {
            Write-LifecycleAuditLog -EventType "JOINER" -TargetUserPrincipalName $UserPrincipalName -Action "ProvisionUser" -Status "FAILURE" -Details @{ Error = "UserAlreadyExists" } -Initiator $activeContext.Account
        } catch {
            Write-Warning "Audit logging failed: $($_.Exception.Message)"
        }
        exit 1
    } else {
        Write-Host "  -> Confirmed: '$UserPrincipalName' does not exist in directory (HTTP 404). Proceeding." -ForegroundColor Gray
    }
} catch {
    Write-Error "[FAIL-CLOSED GATE] Duplicate identity check failed due to directory query failure (not 404): $($_.Exception.Message). Halting provisioning."
    exit 1
}

# 4. Resolve Target Group
Write-Host "`n[Step 2/3] Resolving target RBAC group '$assignedGroup'..." -ForegroundColor Cyan
$groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$assignedGroup'"
try {
    $groupResp = Invoke-MgGraphRequest -Method GET -Uri $groupUri -ErrorAction Stop
} catch {
    Write-Error "[FAIL-CLOSED GATE] Failed querying target group '$assignedGroup' from directory: $($_.Exception.Message)"
    exit 1
}

if (-not $groupResp.value -or @($groupResp.value).Count -eq 0) {
    Write-Error "Target security group '$assignedGroup' was not found in directory. Ensure Phase 0 seeds were executed."
    exit 1
}
if (@($groupResp.value).Count -gt 1) {
    Write-Error "[AMBIGUOUS GROUP ERROR] Multiple groups ($(@($groupResp.value).Count)) share display name '$assignedGroup'. Cannot resolve target group."
    exit 1
}
$targetGroupId = $groupResp.value[0].id
Write-Host "  -> Group Verified: $assignedGroup (ID: $targetGroupId)" -ForegroundColor Gray

# 5. Provision User with High-Entropy Password
Write-Host "`n[Step 3/3] Provisioning user account in Entra ID..." -ForegroundColor Cyan
$tempPassword = New-SecureTemporaryPassword -Length 24

$newUserPayload = @{
    accountEnabled    = $true
    displayName       = $displayName
    givenName         = $GivenName
    surname           = $Surname
    userPrincipalName = $UserPrincipalName
    mailNickname      = $mailNickname
    department        = $Department
    jobTitle          = $JobTitle
    usageLocation     = $UsageLocation
    passwordProfile   = @{
        forceChangePasswordNextSignIn = $true
        password                      = $tempPassword
    }
}

$createdUserId = $null

try {
    $createUri = "https://graph.microsoft.com/v1.0/users"
    $jsonPayload = $newUserPayload | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Create Microsoft Entra ID user account")) {
        $createdUser = Invoke-MgGraphRequest -Method POST -Uri $createUri -Body $jsonPayload -ContentType "application/json" -ErrorAction Stop
        $createdUserId = $createdUser.id
        Write-Host "  -> Successfully created user object (ID: $createdUserId)" -ForegroundColor Green
    } else {
        Write-Host "  [WhatIf] Would create user object for $UserPrincipalName" -ForegroundColor Yellow
    }

    # Assign to Security Group
    if ($createdUserId -and $PSCmdlet.ShouldProcess($UserPrincipalName, "Assign membership in security group '$assignedGroup'")) {
        $addGroupMemberUri = "https://graph.microsoft.com/v1.0/groups/$targetGroupId/members/`$ref"
        $memberPayload = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$createdUserId"
        } | ConvertTo-Json

        try {
            Invoke-MgGraphRequest -Method POST -Uri $addGroupMemberUri -Body $memberPayload -ContentType "application/json" -ErrorAction Stop
            Write-Host "  -> Assigned membership to group: $assignedGroup" -ForegroundColor Green
        } catch {
            # Compensating Action: Contain/Quarantine newly created account to prevent orphaned active identities (Item 8)
            $groupError = $_.Exception.Message
            Write-Warning "[COMPENSATING ACTION] Group assignment failed! Disabling and quarantining newly created identity '$createdUserId'..."
            $quarantinePayload = @{
                accountEnabled = $false
                jobTitle       = "Quarantine - ProvisioningFailed"
            } | ConvertTo-Json

            $quarantineConfirmed = $false
            $quarantineError = $null

            try {
                Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$createdUserId" -Body $quarantinePayload -ContentType "application/json" -ErrorAction Stop | Out-Null

                # Re-query user to verify account is disabled (fail-closed verification)
                $verifyUserUri = "https://graph.microsoft.com/v1.0/users/$createdUserId`?`$select=id,accountEnabled,jobTitle"
                $verifiedUser = Invoke-MgGraphRequest -Method GET -Uri $verifyUserUri -ErrorAction Stop
                if ($verifiedUser -and $verifiedUser.accountEnabled -eq $false) {
                    $quarantineConfirmed = $true
                    Write-Host "  -> [VERIFIED] Compensating quarantine confirmed: Account is disabled (accountEnabled = False)." -ForegroundColor Green
                } else {
                    $quarantineError = "Post-quarantine query returned accountEnabled = $($verifiedUser.accountEnabled)"
                }
            } catch {
                $quarantineError = $_.Exception.Message
            }

            if ($quarantineConfirmed) {
                Write-LifecycleAuditLog -EventType "JOINER" `
                                        -TargetUserPrincipalName $UserPrincipalName `
                                        -TargetUserId $createdUserId `
                                        -Action "OnboardUser" `
                                        -Status "COMPENSATED_FAILURE" `
                                        -Details @{
                                            Error = "GroupAssignmentFailed"
                                            CompensatingAction = "AccountDisabledAndQuarantined"
                                            Verification = "ConfirmedDisabled"
                                            OriginalError = $groupError
                                        } `
                                        -Initiator $activeContext.Account
                throw "Compensating action triggered: User '$UserPrincipalName' was safely quarantined (accountEnabled = False) because group assignment failed: $groupError"
            } else {
                Write-LifecycleAuditLog -EventType "JOINER" `
                                        -TargetUserPrincipalName $UserPrincipalName `
                                        -TargetUserId $createdUserId `
                                        -Action "OnboardUser" `
                                        -Status "QUARANTINE_FAILED" `
                                        -Details @{
                                            Error = "GroupAssignmentFailed"
                                            CompensatingAction = "QuarantineFailed"
                                            Verification = "FailedToConfirmDisabled"
                                            OriginalError = $groupError
                                            QuarantineError = $quarantineError
                                        } `
                                        -Initiator $activeContext.Account
                throw "[CRITICAL SECURITY FAILURE] Compensating quarantine could NOT be verified for user '$UserPrincipalName' (ID: $createdUserId). Account may remain enabled without proper RBAC groups! Immediate manual containment required: $quarantineError (Original Error: $groupError)"
            }
        }
    }

    # Finding 9: Audit failure handling must make audit failure visible in final transaction state
    $auditLogged = $true
    try {
        Write-LifecycleAuditLog -EventType "JOINER" `
                                -TargetUserPrincipalName $UserPrincipalName `
                                -TargetUserId $createdUserId `
                                -Action "OnboardUser" `
                                -Status "SUCCESS" `
                                -Details @{
                                    Department       = $Department
                                    JobTitle         = $JobTitle
                                    AssignedGroup    = $assignedGroup
                                    CredentialPolicy = "forceChangePasswordNextSignIn"
                                } `
                                -Initiator $activeContext.Account
    } catch {
        $auditLogged = $false
        Write-Error "[AUDIT LOGGING FAILURE] User '$UserPrincipalName' was provisioned in Entra ID, but audit record write failed: $($_.Exception.Message)"
    }

    if (-not $auditLogged) {
        Write-Host "`n[TRANSACTION STATE: PARTIALLY COMPLETED - AUDIT RECORD FAILED]" -ForegroundColor Yellow
        exit 2
    }

    # Display Provisioning Credential Packet (Zero cleartext password exposure - Finding 8)
    Write-Host "`n================ ONBOARDING CREDENTIAL PACKET ================" -ForegroundColor White
    Write-Host "User Principal Name : $UserPrincipalName" -ForegroundColor Cyan
    Write-Host "Display Name        : $displayName" -ForegroundColor Cyan
    Write-Host "Assigned RBAC Group : $assignedGroup" -ForegroundColor Cyan
    Write-Host "Temporary Credential: [SECURELY GENERATED - Enforced forceChangePasswordNextSignIn]" -ForegroundColor Green
    Write-Host "Password Policy     : Mandatory change required on first sign-in" -ForegroundColor Gray
    Write-Host "Conditional Access  : Enforced under baseline workforce MFA (CAP-007)" -ForegroundColor Gray
    Write-Host "Security Posture    : Zero cleartext credential exposure logged or displayed" -ForegroundColor Green
    Write-Host "==============================================================" -ForegroundColor White

} catch {
    Write-Error "Failed to provision user: $($_.Exception.Message)"
    Write-LifecycleAuditLog -EventType "JOINER" `
                            -TargetUserPrincipalName $UserPrincipalName `
                            -TargetUserId $createdUserId `
                            -Action "OnboardUser" `
                            -Status "FAILURE" `
                            -Details @{ Error = $_.Exception.Message } `
                            -Initiator $activeContext.Account
    exit 1
} finally {
    # Secure memory cleanup
    $tempPassword = $null
    $newUserPayload.passwordProfile.password = $null
}
