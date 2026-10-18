<#
.SYNOPSIS
    Microsoft Entra ID Privileged Identity Management (PIM) Configuration & Automation Engine.
.DESCRIPTION
    Automates and models Zero Standing Access (ZSA) role governance:
    - Queries directory roles and current PIM eligibility schedules.
    - Provisions PIM Eligible assignments via Microsoft Graph API.
    - Enforces JIT constraints (max 4-hour activation, justification required, step-up MFA).
    - Provides explicit Entra ID admin center portal configuration procedures.
.PARAMETER AssignEligible
    Switch to assign an eligible PIM role to a user.
.PARAMETER UserPrincipalName
    The UPN of the user to make eligible.
.PARAMETER RoleName
    The display name of the directory role (e.g., 'Conditional Access Administrator', 'Security Administrator').
.PARAMETER EligibilityExpirationType
    Expiration type for the eligibility window: 'noExpiration' (default, permanent eligibility) or 'afterDuration'.
.PARAMETER EligibilityDuration
    ISO 8601 duration string if EligibilityExpirationType is 'afterDuration' (e.g. 'P365D' for 1 year). Default is 'P365D'.
.PARAMETER DeviceCode
    Use device authentication flow for Graph connection.
#>

[CmdletBinding()]
param (
    [switch]$AssignEligible,
    [string]$UserPrincipalName,
    [string]$RoleName = "Conditional Access Administrator",
    [ValidateSet("afterDuration", "noExpiration")]
    [string]$EligibilityExpirationType = "afterDuration",
    [string]$EligibilityDuration = "P90D",
    [string]$PermanentJustification,
    [string]$PermanentOwner,
    [string]$PermanentReviewDate,
    [string]$PermanentApprovedBy,
    [switch]$ListRoles,
    [switch]$VerifyPolicyRules,
    [switch]$DeviceCode
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Microsoft Entra Privileged Identity Management (PIM) Engine" -ForegroundColor Cyan
Write-Host "  Zero Standing Access (ZSA) Lifecycle Management" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Connect to Microsoft Graph
$activeContext = Get-MgContext -ErrorAction SilentlyContinue
# Least-Privilege Scopes: Drop broad Directory.ReadWrite.All in favor of granular role management & user read
$requiredScopes = @(
    "RoleManagement.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleManagementPolicy.Read.Directory",
    "User.Read.All"
)

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
    Write-Host "`n[Authentication] Connecting to Microsoft Graph with granular least-privilege PIM scopes..." -ForegroundColor Yellow
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

Write-Host "Connected Tenant: $($activeContext.TenantId)" -ForegroundColor Green

# 2. Query Directory Roles
$roleDefsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$RoleName'"
$roleDefResp = Invoke-MgGraphRequest -Method GET -Uri $roleDefsUri

if (-not $roleDefResp.value -or $roleDefResp.value.Count -eq 0) {
    Write-Error "Role '$RoleName' not found in tenant. Use -ListRoles to view available role definitions."
    exit 1
}

$targetRole = $roleDefResp.value[0]
Write-Host "`n[Target Role Identified]:" -ForegroundColor Cyan
Write-Host "  Display Name: $($targetRole.displayName)" -ForegroundColor White
Write-Host "  Role ID     : $($targetRole.id)" -ForegroundColor White
Write-Host "  Template ID : $($targetRole.templateId)" -ForegroundColor White

if ($ListRoles) {
    Write-Host "`nQuerying all available directory roles..." -ForegroundColor Cyan
    $allRolesUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
    $allRolesResp = Invoke-MgGraphRequest -Method GET -Uri $allRolesUri
    $allRolesResp.value | Select-Object displayName, id, templateId | Format-Table -AutoSize
    exit 0
}

function Test-PimRoleActivationRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$RoleDefinitionId,
        [Parameter(Mandatory=$true)]
        [string]$RoleDisplayName
    )

    Write-Host "`n[PIM Rule Verification] Inspecting activation policy constraints for '$RoleDisplayName'..." -ForegroundColor Cyan
    try {
        $assignUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'"
        $assignResp = Invoke-MgGraphRequest -Method GET -Uri $assignUri -ErrorAction Stop

        if (-not $assignResp.value -or @($assignResp.value).Count -eq 0) {
            Write-Warning "No roleManagementPolicyAssignment discovered for role '$RoleDisplayName'."
            return [PSCustomObject]@{
                Status      = "Failed"
                IsCompliant = $false
                Findings    = @("No roleManagementPolicyAssignment discovered for role '$RoleDisplayName'.")
            }
        }

        $policyId = $assignResp.value[0].policyId
        Write-Host "  -> Discovered Unified Role Management Policy ID: $policyId" -ForegroundColor Gray

        $rulesUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$policyId/rules"
        $rulesResp = Invoke-MgGraphRequest -Method GET -Uri $rulesUri -ErrorAction Stop

        $rules = @($rulesResp.value)
        $complianceResults = [PSCustomObject]@{
            Status                     = "Complete"
            MaxActivationDurationHours = $null
            MfaRequiredOnActivation    = $false
            JustificationRequired      = $false
            TicketRequired             = $false
            ApprovalRequired           = $false
            NotificationsConfigured    = $false
            IsCompliant                = $true
            Findings                   = [System.Collections.Generic.List[string]]::new()
        }

        $tier0Roles = @("Global Administrator", "Conditional Access Administrator", "Privileged Role Administrator", "Security Administrator")

        foreach ($rule in $rules) {
            $ruleType = $rule.'@odata.type'

            # 1. Check Expiration Rule for EndUser activation (Max 4h)
            if ($ruleType -eq "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule" -and $rule.target.caller -eq "EndUser") {
                $durationStr = $rule.maximumDuration
                if ($durationStr -match "PT(\d+)H") {
                    $hours = [int]$matches[1]
                    $complianceResults.MaxActivationDurationHours = $hours
                    if ($hours -gt 4) {
                        $complianceResults.IsCompliant = $false
                        $complianceResults.Findings.Add("Max activation duration ($hours hours) exceeds Zero Standing Access benchmark of 4 hours.")
                    }
                } else {
                    $complianceResults.Findings.Add("Non-standard expiration duration string: $durationStr")
                }
            }

            # 2. Check Enablement Rule for MFA, Justification, and Ticketing
            if ($ruleType -eq "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule" -and $rule.target.caller -eq "EndUser") {
                $enabled = @($rule.enabledRules)
                if ($enabled -contains "MultiFactorAuthentication") {
                    $complianceResults.MfaRequiredOnActivation = $true
                } else {
                    $complianceResults.IsCompliant = $false
                    $complianceResults.Findings.Add("MFA is not enforced upon role activation in PIM role settings.")
                }

                if ($enabled -contains "Justification") {
                    $complianceResults.JustificationRequired = $true
                } else {
                    $complianceResults.IsCompliant = $false
                    $complianceResults.Findings.Add("Business justification is not mandatory upon role activation.")
                }

                if ($enabled -contains "Ticketing") {
                    $complianceResults.TicketRequired = $true
                }
            }

            # 3. Check Approval Rule
            if ($ruleType -eq "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule" -and $rule.target.caller -eq "EndUser") {
                if ($rule.setting -and $rule.setting.isApprovalRequired) {
                    $complianceResults.ApprovalRequired = $true
                }
            }

            # 4. Check Notification Rule
            if ($ruleType -eq "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule") {
                $complianceResults.NotificationsConfigured = $true
            }
        }

        # Assert Tier-0 approval requirements
        if ($RoleDisplayName -in $tier0Roles -and -not $complianceResults.ApprovalRequired) {
            $complianceResults.IsCompliant = $false
            $complianceResults.Findings.Add("Approval sign-off is mandatory for Tier-0 privileged role '$RoleDisplayName' under Zero Standing Access rules.")
        }

        Write-Host "  -> Max Activation Duration: $(if ($complianceResults.MaxActivationDurationHours) { "$($complianceResults.MaxActivationDurationHours) Hours" } else { "Not explicitly configured" })" -ForegroundColor White
        Write-Host "  -> MFA on Activation      : $($complianceResults.MfaRequiredOnActivation)" -ForegroundColor White
        Write-Host "  -> Justification Required : $($complianceResults.JustificationRequired)" -ForegroundColor White
        Write-Host "  -> Ticket Required        : $($complianceResults.TicketRequired)" -ForegroundColor White
        Write-Host "  -> Approver Sign-Off      : $($complianceResults.ApprovalRequired)" -ForegroundColor White
        Write-Host "  -> Notifications Active   : $($complianceResults.NotificationsConfigured)" -ForegroundColor White

        if ($complianceResults.IsCompliant -and $complianceResults.Findings.Count -eq 0) {
            Write-Host "  [VERIFIED] Role activation settings comply with Zero Standing Access standards." -ForegroundColor Green
        } else {
            Write-Warning "  [COMPLIANCE AUDIT] Role activation policy findings:"
            foreach ($finding in $complianceResults.Findings) {
                Write-Warning "    * $finding"
            }
            Write-Host "  -> Portal Path: Microsoft Entra Admin Center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Roles > '$RoleDisplayName' > Role settings > Edit" -ForegroundColor Yellow
        }

        return $complianceResults
    } catch {
        Write-Warning "  -> [UNKNOWN/FAILED] Querying roleManagementPolicies failed: $($_.Exception.Message)"
        Write-Host "  -> Ensure RoleManagementPolicy.Read.Directory permission is granted and Entra ID P2 license is active." -ForegroundColor Yellow
        return [PSCustomObject]@{
            Status      = "Unknown"
            IsCompliant = $false
            Findings    = @("Graph lookup failed or role policy assignment missing: $($_.Exception.Message)")
        }
    }
}

if ($VerifyPolicyRules) {
    $ruleResults = Test-PimRoleActivationRule -RoleDefinitionId $targetRole.id -RoleDisplayName $targetRole.displayName
    if (-not $ruleResults.IsCompliant -or $ruleResults.Status -eq "Unknown") {
        Write-Error "[PIM VERIFY FAILURE] Role activation policy rules for '$($targetRole.displayName)' do not meet Zero Standing Access standards."
        exit 1
    }
    Write-Host "[PIM VERIFY SUCCESS] Role activation policy rules for '$($targetRole.displayName)' verified compliant." -ForegroundColor Green
    exit 0
}

# 3. Handle Eligible Role Assignment & Verification
if ($AssignEligible) {
    if (-not $UserPrincipalName) {
        Write-Error "Parameter -UserPrincipalName is required when using -AssignEligible."
        exit 1
    }

    if ($EligibilityExpirationType -eq "noExpiration") {
        $missingFields = [System.Collections.Generic.List[string]]::new()
        if ([string]::IsNullOrWhiteSpace($PermanentJustification)) { $missingFields.Add("-PermanentJustification") }
        if ([string]::IsNullOrWhiteSpace($PermanentOwner)) { $missingFields.Add("-PermanentOwner") }
        if ([string]::IsNullOrWhiteSpace($PermanentReviewDate)) { $missingFields.Add("-PermanentReviewDate") }
        if ([string]::IsNullOrWhiteSpace($PermanentApprovedBy)) { $missingFields.Add("-PermanentApprovedBy") }

        if ($missingFields.Count -gt 0) {
            Write-Error "[SECURITY POLICY GATE] Zero Standing Access policy restricts permanent PIM eligibility ('noExpiration'). An approved exception record is required. Missing mandatory fields: $($missingFields -join ', '). Bounded eligibility ('afterDuration', e.g. -EligibilityDuration 'P90D') is the enforced enterprise standard."
            exit 1
        }
        Write-Warning "[PIM EXCEPTION ACTIVE] Permanent eligibility exception registered: Owner='$PermanentOwner', Approver='$PermanentApprovedBy', ReviewDate='$PermanentReviewDate', Justification='$PermanentJustification'."
    }

    Write-Host "`n[Step 1/3] Resolving Principal '$UserPrincipalName'..." -ForegroundColor Cyan
    $userUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
    try {
        $userObj = Invoke-MgGraphRequest -Method GET -Uri $userUri
    } catch {
        Write-Error "Could not find user '$UserPrincipalName': $_"
        exit 1
    }

    Write-Host "  -> Principal ID: $($userObj.id) ($($userObj.displayName))" -ForegroundColor Gray

    Write-Host "`n[Step 2/3] Submitting PIM Role Eligibility Schedule Request..." -ForegroundColor Cyan
    $scheduleRequestUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
    
    $expirationObj = if ($EligibilityExpirationType -eq "noExpiration") {
        @{ type = "noExpiration" }
    } else {
        @{
            type = "afterDuration"
            duration = $EligibilityDuration
        }
    }

    $payload = @{
        action = "adminAssign"
        justification = "Zero Standing Access enterprise security baseline - Phase 3 PIM transition."
        roleDefinitionId = $targetRole.id
        directoryScopeId = "/"
        principalId = $userObj.id
        scheduleInfo = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString("o")
            expiration = $expirationObj
        }
    }

    try {
        $jsonBody = $payload | ConvertTo-Json -Depth 5
        $pimResp = Invoke-MgGraphRequest -Method POST -Uri $scheduleRequestUri -Body $jsonBody -ContentType "application/json" -ErrorAction Stop
        Write-Host "  -> Successfully submitted PIM Eligible role request!" -ForegroundColor Green
        Write-Host "     Eligibility Request ID: $($pimResp.id)" -ForegroundColor Gray
        Write-Host "     Status                 : $($pimResp.status)" -ForegroundColor Green

        # Step 3: Post-Assignment Verification Gate (Explicit 4-State Verification)
        Write-Host "`n[Step 3/3] Verifying Active Role Eligibility Schedule Instance..." -ForegroundColor Cyan
        $instancesUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($userObj.id)' and roleDefinitionId eq '$($targetRole.id)'"
        $verificationState = "Unknown"

        try {
            $instancesResp = Invoke-MgGraphRequest -Method GET -Uri $instancesUri -ErrorAction Stop
            if ($instancesResp.value -and @($instancesResp.value).Count -gt 0) {
                $inst = $instancesResp.value[0]
                $verificationState = "Assignment confirmed"
                Write-Host "  [VERIFIED] Role Eligibility Schedule confirmed active in tenant!" -ForegroundColor Green
                Write-Host "  Verification State   : $verificationState" -ForegroundColor Green
                Write-Host "  Schedule Instance ID : $($inst.id)" -ForegroundColor White
                Write-Host "  Member Type          : $($inst.memberType)" -ForegroundColor White
                Write-Host "  Start Date (UTC)     : $($inst.startDateTime)" -ForegroundColor White
            } else {
                $verificationState = "Assignment pending propagation"
                Write-Warning "  [VERIFY WARNING] Schedule instance not found immediately ($verificationState). Directory propagation may be in progress."
            }
        } catch {
            $verificationState = "Verification unavailable"
            Write-Error "  [VERIFY ERROR] Verification read failed: $($_.Exception.Message). State: $verificationState."
        }

        Write-Host "  Final Eligibility State: $verificationState" -ForegroundColor $(if($verificationState -eq 'Assignment confirmed'){'Green'}elseif($verificationState -eq 'Assignment pending propagation'){'Yellow'}else{'Red'})

        # Step 4: Audit role activation constraints
        $ruleResults = Test-PimRoleActivationRule -RoleDefinitionId $targetRole.id -RoleDisplayName $targetRole.displayName
        if (-not $ruleResults.IsCompliant -or $ruleResults.Status -eq "Unknown") {
            Write-Warning "  [PIM COMPLIANCE WARNING] Role activation policy has compliance findings for '$($targetRole.displayName)'."
        }

        if ($verificationState -eq "Verification unavailable" -or $verificationState -eq "Assignment failed") {
            Write-Error "[PIM ASSIGNMENT INCOMPLETE] Final eligibility verification state was '$verificationState'."
            exit 1
        }
    } catch {
        $verificationState = "Assignment failed"
        Write-Error "  [ASSIGNMENT FAILED] PIM Graph Request returned: $($_.Exception.Message). State: $verificationState."
        exit 1
    }
}

Write-Host "`n================ PIM ZERO STANDING ACCESS ARCHITECTURE ================" -ForegroundColor White
Write-Host "Operational Separation of Responsibilities (Finding D Remediated):" -ForegroundColor Cyan
Write-Host "  1. Programmatic API Layer (/roleEligibilityScheduleRequests):" -ForegroundColor White
Write-Host "      * Assigns identity ELIGIBILITY to request role elevation (Expiration: $EligibilityExpirationType)." -ForegroundColor Gray
Write-Host "      * Does NOT define role activation constraints (duration, MFA, approvals)." -ForegroundColor Gray
Write-Host "  2. Entra ID Role Setting Policy Layer (unifiedRoleManagementPolicyRules):" -ForegroundColor White
Write-Host "      * Max Activation Duration : 4 Hours (enforced at activation prompt, NOT assignment payload)" -ForegroundColor Yellow
Write-Host "      * Authentication Context  : Require Phishing-Resistant MFA (CAP-002)" -ForegroundColor Yellow
Write-Host "      * Approval & Ticketing    : Mandatory business justification & approver sign-off" -ForegroundColor Yellow
Write-Host "      * Configured via          : Microsoft Entra Admin Center -> Identity Governance -> PIM -> Role Settings" -ForegroundColor Yellow
Write-Host "========================================================================" -ForegroundColor White
