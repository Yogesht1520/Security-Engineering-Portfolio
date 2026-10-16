<#
.SYNOPSIS
    Enterprise Identity-as-Code (IaC) Deployment Engine for Microsoft Entra Conditional Access.
.DESCRIPTION
    Declarative policy orchestration engine implementing Zero Trust safe staging:
    - Validates policy definitions against JSON Schema.
    - Resolves both include and exclude group/user/location references via centralized resolvers.
    - Validates mandatory emergency break-glass exclusion controls.
    - Generates pre-deployment diffs and drift reports against live Entra state.
    - Creates immutable pre-deployment rollback snapshots.
    - Supports CI/CD dry runs (-ValidateOnly), deployment planning (-Plan / -WhatIf), and progressive execution.
.PARAMETER PoliciesPath
    Path to directory containing policy JSON files.
.PARAMETER ValidateOnly
    Validates schemas and reference integrity locally without Graph network calls.
.PARAMETER Plan
    Connects to Graph, resolves live identifiers, and outputs before/after diffs without changes.
.PARAMETER Deploy
    Applies declarative changes to Microsoft Entra ID.
.PARAMETER Environment
    Target environment profile ('Lab', 'Staging', 'Production'). Default is 'Lab'.
.PARAMETER PolicyId
    Filters deployment to a single policy (e.g. 'CAP-001').
.PARAMETER Force
    Bypasses interactive confirmation during -Deploy.
#>

[CmdletBinding(DefaultParameterSetName="Plan")]
param (
    [string]$PoliciesPath,

    [switch]$ValidateOnly,

    [switch]$Plan,

    [switch]$Deploy,

    [ValidateSet("Lab", "Staging", "Production")]
    [string]$Environment = "Lab",

    [string]$PolicyId,

    [switch]$DeviceCode,

    [switch]$Force,

    [switch]$OnlyExportFunctions
)

function Invoke-PolicyDeploymentTransaction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$ActionsToTake,
        [Parameter(Mandatory=$true)]
        [string]$SnapshotId,
        [Parameter(Mandatory=$true)]
        [string]$RollbackScript,
        [Parameter(Mandatory=$false)]
        $ActiveContext = $null,
        [string]$ReceiptsDirectory,
        [string]$SnapshotsDir
    )

    if ([string]::IsNullOrWhiteSpace($ReceiptsDirectory)) {
        $ReceiptsDirectory = Join-Path $PSScriptRoot "..\..\reports"
    }
    if ([string]::IsNullOrWhiteSpace($SnapshotsDir)) {
        $SnapshotsDir = Join-Path $PSScriptRoot "..\..\snapshots"
    }

    Write-Host "`nExecuting Live Policy Deployment with Per-Policy Transaction Tracking..." -ForegroundColor Cyan
    $transactionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $deploymentFailed = $false
    $failureReason = $null
    $newlyCreatedPolicyIds = [System.Collections.Generic.List[string]]::new()
    $mutationsApplied = 0

    foreach ($item in $ActionsToTake) {
        if ($deploymentFailed) {
            Write-Host "  [SKIPPING] $($item.DisplayName) (Action: $($item.Action)) - Transaction halted due to preceding failure." -ForegroundColor DarkGray
            $transactionResults.Add([PSCustomObject]@{
                DisplayName = $item.DisplayName
                Action      = $item.Action
                Status      = "Skipped"
                PolicyId    = $item.PolicyId
                Message     = "Halted: Prior step failed ($failureReason)"
            })
            continue
        }

        if ($item.Action -eq "Skip") {
            Write-Host "  [In Sync] $($item.DisplayName) - Zero drift. Skipped mutation." -ForegroundColor Gray
            $transactionResults.Add([PSCustomObject]@{
                DisplayName = $item.DisplayName
                Action      = "Skip"
                Status      = "SkippedNoDrift"
                PolicyId    = $item.PolicyId
                Message     = "In parity with desired state"
            })
            continue
        }

        $jsonBody = $item.Payload | ConvertTo-Json -Depth 10

        if ($item.Action -eq "Update") {
            Write-Host "  [Updating] $($item.DisplayName) (ID: $($item.PolicyId))..." -ForegroundColor Yellow
            $patchUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($item.PolicyId)"
            try {
                Invoke-MgGraphRequest -Method PATCH -Uri $patchUri -Body $jsonBody -ContentType "application/json" -ErrorAction Stop | Out-Null
                Write-Host "  -> Successfully updated." -ForegroundColor Green
                $mutationsApplied++
                $transactionResults.Add([PSCustomObject]@{
                    DisplayName = $item.DisplayName
                    Action      = "Update"
                    Status      = "Success"
                    PolicyId    = $item.PolicyId
                    Message     = "OK"
                })
            } catch {
                $deploymentFailed = $true
                $failureReason = $_.Exception.Message
                Write-Host "  -> FAILED to update: $failureReason" -ForegroundColor Red

                # Ambiguous Write Mitigation: Check whether server applied change prior to connection loss
                try {
                    $verifyUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($item.PolicyId)"
                    $livePol = Invoke-MgGraphRequest -Method GET -Uri $verifyUri -ErrorAction Stop
                    $snapshotFile = if ($SnapshotsDir -and (Test-Path (Join-Path $SnapshotsDir "$SnapshotId\$($item.DisplayName).json"))) {
                        Get-Content (Join-Path $SnapshotsDir "$SnapshotId\$($item.DisplayName).json") -Raw | ConvertFrom-Json
                    } else { $null }

                    if ($snapshotFile -and $livePol) {
                        # Strip server-generated metadata and compare canonical state
                        $cleanLive = $livePol.PSObject.Copy()
                        $cleanSnap = $snapshotFile.PSObject.Copy()
                        foreach ($prop in @("id", "createdDateTime", "modifiedDateTime", "@odata.context", "@odata.nextLink")) {
                            $cleanLive.PSObject.Properties.Remove($prop)
                            $cleanSnap.PSObject.Properties.Remove($prop)
                        }
                        $liveJson = $cleanLive | ConvertTo-Json -Depth 10 -Compress
                        $snapJson = $cleanSnap | ConvertTo-Json -Depth 10 -Compress

                        if ($liveJson -ne $snapJson) {
                            $mutationsApplied++
                            Write-Warning "  -> [AMBIGUOUS WRITE DETECTED] Server applied update prior to connection loss! Live state differs from pre-deployment snapshot. Flagged for mandatory rollback."
                        } else {
                            Write-Host "  -> [CONFIRMED UNMUTATED] Live policy state is identical to pre-deployment snapshot. Write was not committed." -ForegroundColor Gray
                        }
                    } else {
                        $mutationsApplied++
                        Write-Warning "  -> [AMBIGUOUS WRITE DETECTED] Live policy exists; treating as potentially applied for fail-safe rollback."
                    }
                } catch {
                    $mutationsApplied++
                    Write-Warning "  -> [AMBIGUOUS STATE] Unable to verify write state via Graph query ($($_.Exception.Message)). Treating as potentially applied for fail-safe rollback."
                }

                $transactionResults.Add([PSCustomObject]@{
                    DisplayName = $item.DisplayName
                    Action      = "Update"
                    Status      = "Failed"
                    PolicyId    = $item.PolicyId
                    Message     = $failureReason
                })
            }
        } else {
            Write-Host "  [Creating] $($item.DisplayName)..." -ForegroundColor Cyan
            $postUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            try {
                $created = Invoke-MgGraphRequest -Method POST -Uri $postUri -Body $jsonBody -ContentType "application/json" -ErrorAction Stop
                $createdId = $created.id
                $newlyCreatedPolicyIds.Add($createdId)
                $mutationsApplied++
                Write-Host "  -> Successfully created (ID: $createdId)." -ForegroundColor Green
                $transactionResults.Add([PSCustomObject]@{
                    DisplayName = $item.DisplayName
                    Action      = "Create"
                    Status      = "Success"
                    PolicyId    = $createdId
                    Message     = "Created successfully"
                })
            } catch {
                $deploymentFailed = $true
                $failureReason = $_.Exception.Message
                Write-Host "  -> FAILED to create: $failureReason" -ForegroundColor Red

                # Ambiguous Creation Mitigation: Check if policy was created despite response loss
                try {
                    $checkListUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                    $currentList = Invoke-MgGraphRequest -Method GET -Uri $checkListUri -ErrorAction Stop
                    $ambiguousMatches = @($currentList.value | Where-Object { $_.displayName -eq $item.DisplayName })
                    if ($ambiguousMatches.Count -gt 0) {
                        foreach ($am in $ambiguousMatches) {
                            if (-not $newlyCreatedPolicyIds.Contains($am.id)) {
                                $newlyCreatedPolicyIds.Add($am.id)
                            }
                        }
                        $mutationsApplied++
                        Write-Warning "  -> [AMBIGUOUS WRITE DETECTED] Policy created before response drop! Added ID(s) to cleanup list."
                    }
                } catch {
                    $mutationsApplied++
                    Write-Warning "  -> [AMBIGUOUS STATE] Unable to verify creation state. Assuming mutation applied."
                }

                $transactionResults.Add([PSCustomObject]@{
                    DisplayName = $item.DisplayName
                    Action      = "Create"
                    Status      = "Failed"
                    PolicyId    = $null
                    Message     = $failureReason
                })
            }
        }
    }

    Write-Host "`n================ PER-POLICY TRANSACTION SUMMARY ================" -ForegroundColor Cyan
    $transactionResults | Format-Table -Property DisplayName, Action, Status, Message -AutoSize

    # 8. Automatic In-Flight Rollback & Transaction State Machine
    $transactionState = "Completed"
    $rollbackExecuted = $false
    $rollbackVerified = $false

    if ($deploymentFailed) {
        Write-Host "`n[DEPLOYMENT FAILED] One or more policies encountered errors during deployment!" -ForegroundColor Red
        Write-Host "Transaction halted immediately. Beginning automatic in-flight rollback..." -ForegroundColor Red

        if ($mutationsApplied -gt 0 -or $newlyCreatedPolicyIds.Count -gt 0) {
            $rollbackExecuted = $true
            Write-Host "`n[AUTOMATIC ROLLBACK TRIGGERED] Restoring tenant to pre-deployment snapshot '$SnapshotId'..." -ForegroundColor Yellow
            try {
                $rollbackResult = & $RollbackScript -Action Restore -SnapshotId $SnapshotId -SnapshotsDir $SnapshotsDir -SessionCreatedPolicyIds $newlyCreatedPolicyIds
                if ($rollbackResult -eq $true) {
                    $rollbackVerified = $true
                    $transactionState = "FailedAndRolledBack"
                    Write-Host "`n[ROLLBACK SUCCESS] Automatic rollback completed and live state verified restored!" -ForegroundColor Green
                } else {
                    $transactionState = "PendingVerification"
                    Write-Warning "`n[ROLLBACK WARNING] Rollback completed but live verification returned warnings."
                }
            } catch {
                $transactionState = "RollbackFailed"
                Write-Error "`n[CRITICAL ROLLBACK FAILURE] Automatic rollback encountered an error: $($_.Exception.Message)"
            }
        } else {
            $transactionState = "FailedAndRolledBack"
            Write-Host "Zero tenant mutations were applied prior to failure. Snapshot baseline is intact." -ForegroundColor Green
        }
    }

    # 9. Persist Formal Deployment Transaction Receipt
    if (-not (Test-Path $ReceiptsDirectory)) { New-Item -ItemType Directory -Path $ReceiptsDirectory -Force | Out-Null }
    $receiptTimestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $receiptFile = Join-Path $ReceiptsDirectory "deployment_receipt_$receiptTimestamp.json"

    $tId = if ($ActiveContext) { $ActiveContext.TenantId } else { "unknown" }
    $acc = if ($ActiveContext) { $ActiveContext.Account } else { "automated-runner" }

    $receipt = [PSCustomObject]@{
        TransactionId            = [Guid]::NewGuid().ToString()
        TimestampUtc             = (Get-Date).ToUniversalTime().ToString("o")
        TenantId                 = $tId
        Operator                 = $acc
        OverallTransactionState  = $transactionState
        SnapshotId               = $SnapshotId
        MutationsAttempted       = $ActionsToTake.Count
        MutationsApplied         = $mutationsApplied
        CreatedPolicyIds         = $newlyCreatedPolicyIds
        RollbackExecuted         = $rollbackExecuted
        RollbackVerified         = $rollbackVerified
        FailureReason            = $failureReason
        PolicyTransactions       = $transactionResults
    }

    $receipt | ConvertTo-Json -Depth 5 | Out-File -FilePath $receiptFile -Encoding utf8
    Write-Host "`n[TRANSACTION RECEIPT] Audit receipt saved: $receiptFile" -ForegroundColor Cyan

    return [PSCustomObject]@{
        TransactionState = $transactionState
        Receipt          = $receipt
        ReceiptFile      = $receiptFile
    }
}

if ($OnlyExportFunctions) {
    return
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Identity-as-Code Engine (Microsoft Entra ID) " -ForegroundColor Cyan
Write-Host "  Environment: $Environment | Mode: $(if($ValidateOnly){'ValidateOnly'}elseif($Deploy){'Deploy'}else{'Plan/WhatIf'})" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Resolve Policy Directory
if ([string]::IsNullOrWhiteSpace($PoliciesPath)) {
    $PoliciesPath = Join-Path $PSScriptRoot "..\..\policies"
}
$resolvedPoliciesPath = Resolve-Path $PoliciesPath -ErrorAction SilentlyContinue
if (-not $resolvedPoliciesPath -or -not (Test-Path $resolvedPoliciesPath)) {
    Write-Error "Policies directory not found at $PoliciesPath"
    exit 1
}

$policyFiles = Get-ChildItem -Path $resolvedPoliciesPath -Filter "*.json"
if ($PolicyId) {
    $policyFiles = $policyFiles | Where-Object { $_.Name -like "$PolicyId*.json" -or $_.Name -like "*$PolicyId*.json" }
}

Write-Host "`n[Step 1/5] Loaded $($policyFiles.Count) declarative policy definition(s) from $resolvedPoliciesPath" -ForegroundColor White

# 2. Syntax & Schema Validation Check
Write-Host "`n[Step 2/5] Performing Deep Recursive Schema & Baseline Pre-Flight Validation..." -ForegroundColor Cyan
$parsedPolicies = @()
$schemaFile = Join-Path $PSScriptRoot "..\..\policies\schema\conditional-access.schema.json"
. (Join-Path $PSScriptRoot "validate_schema.ps1")

foreach ($file in $policyFiles) {
    try {
        $rawJson = Get-Content -Path $file.FullName -Raw
        $content = $rawJson | ConvertFrom-Json
        
        # Deep recursive draft-07 JSON Schema validation
        $null = Test-PolicyJsonSchema -JsonData $content -SchemaPath $schemaFile -PolicyFileName $file.Name

        # Check for known unresolvable placeholders
        if ($rawJson -match "emergency-admin-id" -or $rawJson -match "<[A-Z0-9_]+>") {
            throw "Unresolved placeholder detected in $($file.Name). Must resolve before deployment."
        }

        # Mandatory Break-Glass Exclusion Hard Gate for broad/blocking policies
        $hasBroadUsers = $content.conditions.users.includeUsers -and ($content.conditions.users.includeUsers -contains "All")
        $hasBroadRoles = $content.conditions.users.includeRoles -and ($content.conditions.users.includeRoles.Count -gt 0)
        $hasBroadGroups = $content.conditions.users.includeGroups -and ($content.conditions.users.includeGroups -contains "All")

        if ($hasBroadUsers -or $hasBroadRoles -or $hasBroadGroups) {
            $hasBreakGlassExclusion = $content.conditions.users.excludeGroups -and ($content.conditions.users.excludeGroups -contains "SEC-BreakGlass-Exclusion")
            if (-not $hasBreakGlassExclusion) {
                throw "[FAIL-CLOSED GATE] Policy '$($content.displayName)' targets broad users/roles but lacks mandatory 'SEC-BreakGlass-Exclusion' exclusion. Deployment rejected to prevent tenant lockout."
            }
        }

        # Emergency Account Direct Inclusion Check
        if ($content.conditions.users.includeUsers) {
            foreach ($u in $content.conditions.users.includeUsers) {
                if ($u -like "*emergency-admin*" -or $u -like "*breakglass*") {
                    throw "[FAIL-CLOSED GATE] Policy '$($content.displayName)' directly includes emergency account '$u' in includeUsers! Emergency accounts must never be directly targeted."
                }
            }
        }

        $parsedPolicies += [PSCustomObject]@{
            File        = $file.Name
            FilePath    = $file.FullName
            Policy      = $content
            DisplayName = $content.displayName
        }
        Write-Host "  [PASS] Validated definition: $($file.Name) ('$($content.displayName)')" -ForegroundColor Green
    } catch {
        Write-Error "  [FAIL] Schema validation rejected $($file.Name): $($_.Exception.Message)"
        exit 1
    }
}

if ($ValidateOnly) {
    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  [CI/CD Mode] All policy definitions PASSED schema check! " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    exit 0
}

# 3. Connect to Microsoft Graph
Write-Host "`n[Step 3/5] Connecting to Microsoft Graph..." -ForegroundColor Cyan
$requiredScopes = @("Policy.ReadWrite.ConditionalAccess", "Policy.Read.All", "Group.Read.All", "User.Read.All")
$context = Get-MgContext -ErrorAction SilentlyContinue
$hasRequiredScopes = $context -and ($requiredScopes | Where-Object { $context.Scopes -notcontains $_ }).Count -eq 0

if (-not $hasRequiredScopes) {
    Write-Host "Re-authenticating to acquire required Conditional Access scopes..." -ForegroundColor Yellow
    $env:ENTRA_IDENTITY_DISABLE_WAM = "true"
    $tenantConfigFile = Join-Path $PSScriptRoot "..\..\config\tenant.json"
    $tId = if (Test-Path $tenantConfigFile) { (Get-Content $tenantConfigFile -Raw | ConvertFrom-Json).tenantId } else { $null }

    if ($DeviceCode) {
        if ($tId) {
            Connect-MgGraph -TenantId $tId -Scopes $requiredScopes -UseDeviceAuthentication -NoWelcome
        } else {
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication -NoWelcome
        }
    } else {
        if ($tId) {
            Connect-MgGraph -TenantId $tId -Scopes $requiredScopes -NoWelcome
        } else {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        }
    }
}

$activeContext = Get-MgContext
Write-Host "Connected to Tenant ID: $($activeContext.TenantId) as $($activeContext.Account)" -ForegroundColor Green

# Environment Isolation & Multi-Tenant Safety Gate
$tenantConfigFile = Join-Path $PSScriptRoot "..\..\config\tenant.json"
$expectedTenantId = if (Test-Path $tenantConfigFile) {
    (Get-Content $tenantConfigFile -Raw | ConvertFrom-Json).tenantId
} else {
    $env:EXPECTED_ENTRA_TENANT_ID
}

if ($expectedTenantId -and ($activeContext.TenantId -ne $expectedTenantId)) {
    throw "[FAIL-CLOSED ENVIRONMENT GATE] Connected tenant ID '$($activeContext.TenantId)' does not match expected target tenant ID '$expectedTenantId' for environment '$Environment'! Deployment halted to prevent unintended cross-tenant modification."
}

# 4. Reference Resolution (Groups, Users, Named Locations)
Write-Host "`n[Step 4/5] Resolving Identity References against Tenant State..." -ForegroundColor Cyan
$groupResolver    = Join-Path $PSScriptRoot "..\identity\resolve_groups.ps1"
$userResolver     = Join-Path $PSScriptRoot "..\identity\resolve_users.ps1"
$locationResolver = Join-Path $PSScriptRoot "..\identity\resolve_locations.ps1"

foreach ($p in $parsedPolicies) {
    $policy = $p.Policy
    Write-Host "  Resolving references for '$($p.DisplayName)'..." -ForegroundColor Gray

    # Resolve includeGroups
    if ($policy.conditions.users.includeGroups) {
        $res = & $groupResolver -GroupNames $policy.conditions.users.includeGroups -FailOnUnresolved $true
        $policy.conditions.users.includeGroups = $res.ResolvedIds
    }

    # Resolve excludeGroups
    if ($policy.conditions.users.excludeGroups) {
        $res = & $groupResolver -GroupNames $policy.conditions.users.excludeGroups -FailOnUnresolved $true
        $policy.conditions.users.excludeGroups = $res.ResolvedIds
    }

    # Resolve includeUsers
    if ($policy.conditions.users.includeUsers) {
        $res = & $userResolver -UserReferences $policy.conditions.users.includeUsers -FailOnUnresolved $true
        $policy.conditions.users.includeUsers = $res.ResolvedIds
    }

    # Resolve excludeUsers
    if ($policy.conditions.users.excludeUsers) {
        $res = & $userResolver -UserReferences $policy.conditions.users.excludeUsers -FailOnUnresolved $true
        $policy.conditions.users.excludeUsers = $res.ResolvedIds
    }

    # Resolve Locations
    if ($policy.conditions.locations) {
        if ($policy.conditions.locations.includeLocations) {
            $res = & $locationResolver -LocationReferences $policy.conditions.locations.includeLocations -FailOnUnresolved $true
            $policy.conditions.locations.includeLocations = $res.ResolvedIds
        }
        if ($policy.conditions.locations.excludeLocations) {
            $res = & $locationResolver -LocationReferences $policy.conditions.locations.excludeLocations -FailOnUnresolved $true
            $policy.conditions.locations.excludeLocations = $res.ResolvedIds
        }
    }
}
Write-Host "  -> All identity references successfully resolved to active tenant GUIDs." -ForegroundColor Green

# 4.5. Fail-Closed Break-Glass Group & Account Integrity Gate (Finding 1)
Write-Host "`n[Safety Gate] Verifying live emergency break-glass exclusion group & account integrity..." -ForegroundColor Cyan
$bgGroupName = "SEC-BreakGlass-Exclusion"
try {
    $bgSearchUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$bgGroupName'"
    $bgResp = Invoke-MgGraphRequest -Method GET -Uri $bgSearchUri -ErrorAction Stop
    if (-not $bgResp.value -or $bgResp.value.Count -eq 0) {
        throw "[FAIL-CLOSED GATE] Required break-glass exclusion group '$bgGroupName' was not found in live tenant. Deployment aborted to prevent tenant lockout."
    }
    if ($bgResp.value.Count -gt 1) {
        throw "[FAIL-CLOSED GATE] Ambiguity conflict: Multiple groups found with name '$bgGroupName'. Deployment aborted."
    }

    $bgGroupId = $bgResp.value[0].id

    # Implement pagination for break-glass group membership
    $bgMembers = @()
    $membersUri = "https://graph.microsoft.com/v1.0/groups/$bgGroupId/members"
    do {
        $membersResp = Invoke-MgGraphRequest -Method GET -Uri $membersUri -ErrorAction Stop
        if ($membersResp.value) { $bgMembers += $membersResp.value }
        $membersUri = $membersResp.'@odata.nextLink'
    } while ($membersUri)

    if ($bgMembers.Count -eq 0) {
        throw "[FAIL-CLOSED GATE] Break-glass exclusion group '$bgGroupName' has 0 members in live tenant! Cannot safely enforce conditional access without active emergency accounts."
    }

    Write-Host "  [AUDIT] Group '$bgGroupName' (ID: $bgGroupId) contains $($bgMembers.Count) member(s)." -ForegroundColor Gray

    # 1. Verify expected emergency accounts exist, are enabled, and cloud-only
    $expectedAccounts = @("emergency-admin-01", "emergency-admin-02")
    foreach ($accPrefix in $expectedAccounts) {
        $foundMember = $bgMembers | Where-Object { $_.userPrincipalName -like "$accPrefix@*" }
        if (-not $foundMember) {
            # Check if user exists anywhere in tenant
            $usrCheckUri = "https://graph.microsoft.com/v1.0/users?`$filter=startswith(userPrincipalName,'$accPrefix@')&`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled"
            $usrCheck = Invoke-MgGraphRequest -Method GET -Uri $usrCheckUri -ErrorAction Stop
            if (-not $usrCheck.value -or $usrCheck.value.Count -eq 0) {
                throw "[FAIL-CLOSED GATE] Expected emergency account '$accPrefix' does NOT exist in tenant!"
            }
            throw "[FAIL-CLOSED GATE] Emergency account '$accPrefix' exists but is NOT a member of '$bgGroupName'!"
        }

        # Query user attributes to verify cloud-only and enabled state
        $memberDetailUri = "https://graph.microsoft.com/v1.0/users/$($foundMember.id)?`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled"
        $memberDetail = Invoke-MgGraphRequest -Method GET -Uri $memberDetailUri -ErrorAction Stop

        if ($memberDetail.accountEnabled -ne $true) {
            throw "[FAIL-CLOSED GATE] Emergency account '$($memberDetail.userPrincipalName)' is DISABLED in Entra ID! Emergency recovery accounts must be enabled."
        }
        if ($memberDetail.onPremisesSyncEnabled -eq $true) {
            throw "[FAIL-CLOSED GATE] Emergency account '$($memberDetail.userPrincipalName)' is synced from on-premises AD! Emergency accounts must be 100% cloud-only to survive hybrid outages."
        }
        Write-Host "  [PASS] Verified '$($memberDetail.userPrincipalName)' is Active, Cloud-Only, and in '$bgGroupName'." -ForegroundColor Green
    }

    # 2. Purity check: Verify no unauthorized/unexpected members exist in SEC-BreakGlass-Exclusion
    foreach ($m in $bgMembers) {
        $upn = $m.userPrincipalName
        $isExpected = $false
        foreach ($exp in $expectedAccounts) {
            if ($upn -like "$exp@*") { $isExpected = $true; break }
        }
        if (-not $isExpected) {
            throw "[FAIL-CLOSED GATE] Unauthorized user '$upn' discovered in '$bgGroupName'! Only designated emergency accounts may reside in this bypass group."
        }
    }
    Write-Host "  [PASS] Exclusion group purity verified: zero unauthorized members present." -ForegroundColor Green
    Write-Host "  [PASS] Break-glass safety gate PASSED. Dual emergency accounts verified safe." -ForegroundColor Green
} catch {
    # Every inability to verify emergency accounts aborts deployment unconditionally (Finding 1)
    Write-Error "[FAIL-CLOSED BREAK-GLASS GATE] Emergency recovery access verification FAILED: $($_.Exception.Message)"
    Write-Error "Deployment ABORTED to protect tenant recovery capability. (Every inability to verify emergency accounts fails closed)."
    exit 1
}

# 5. Query Live Policies with Pagination Support
Write-Host "`n[Step 5/5] Comparing Desired State with Live Tenant..." -ForegroundColor Cyan
$livePolicies = @()
$uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    if ($response.value) { $livePolicies += $response.value }
    $uri = $response.'@odata.nextLink'
} while ($uri)

$compareScript = Join-Path $PSScriptRoot "compare_policies.ps1"
$actionsToTake = @()

# 5.1. Tri-State Idempotent Action Planner with Ambiguity Detection (Finding 3)
foreach ($p in $parsedPolicies) {
    $displayName = $p.DisplayName
    $policyPrefix = if ($displayName -match "^(CAP-[0-9]{3})") { $Matches[1] } else { $null }

    $matchingPolicies = @($livePolicies | Where-Object { 
        $_.displayName -eq $displayName -or ($policyPrefix -and $_.displayName -like "$policyPrefix*") 
    })

    if ($matchingPolicies.Count -gt 1) {
        Write-Error "[AMBIGUITY CONFLICT] Multiple tenant policies match target '$displayName' (Found $($matchingPolicies.Count) matches). Deployment aborted to prevent arbitrary overwrites."
        exit 1
    }

    $existing = if ($matchingPolicies.Count -eq 1) { $matchingPolicies[0] } else { $null }

    if ($existing) {
        # Check for drift
        $driftResult = & $compareScript -LocalPolicy $p.Policy -LivePolicy $existing
        if ($driftResult.HasDrift) {
            Write-Host "  [DRIFT DETECTED] '$displayName' differs from desired state." -ForegroundColor Yellow
            $actionsToTake += [PSCustomObject]@{
                Action      = "Update"
                DisplayName = $displayName
                PolicyId    = $existing.id
                Payload     = $p.Policy
                HasDrift    = $true
                DriftFields = $driftResult.DriftFields
            }
        } else {
            Write-Host "  [IDENTICAL / IN SYNC] '$displayName' has ZERO drift. (Will be skipped during deployment)." -ForegroundColor DarkGray
            $actionsToTake += [PSCustomObject]@{
                Action      = "Skip"
                DisplayName = $displayName
                PolicyId    = $existing.id
                Payload     = $p.Policy
                HasDrift    = $false
                DriftFields = @()
            }
        }
    } else {
        Write-Host "  [NEW POLICY] '$displayName' will be CREATED in tenant." -ForegroundColor Cyan
        $actionsToTake += [PSCustomObject]@{
            Action      = "Create"
            DisplayName = $displayName
            PolicyId    = $null
            Payload     = $p.Policy
            HasDrift    = $true
            DriftFields = @("NewPolicy")
        }
    }
}

$policiesToCreate = @($actionsToTake | Where-Object { $_.Action -eq "Create" })
$policiesToUpdate = @($actionsToTake | Where-Object { $_.Action -eq "Update" })
$policiesToSkip   = @($actionsToTake | Where-Object { $_.Action -eq "Skip" })

# 6. Execution Gate (Plan vs Deploy)
if (-not $Deploy -or $Plan) {
    Write-Host "`n==========================================================" -ForegroundColor Yellow
    Write-Host "  [PLAN COMPLETE] Execution Summary:                    " -ForegroundColor Yellow
    Write-Host "  Policies to Create       : $($policiesToCreate.Count)" -ForegroundColor White
    Write-Host "  Policies to Update (Drift): $($policiesToUpdate.Count)" -ForegroundColor White
    Write-Host "  Policies to Skip (In Sync): $($policiesToSkip.Count)" -ForegroundColor White
    if ($policiesToCreate.Count -eq 0 -and $policiesToUpdate.Count -eq 0) {
        Write-Host "  -> Tenant state is in 100% parity with desired state. Zero mutations required." -ForegroundColor Green
    } else {
        Write-Host "  Run with -Deploy to apply these changes to Microsoft Entra ID." -ForegroundColor Yellow
    }
    Write-Host "==========================================================" -ForegroundColor Yellow
    exit 0
}

# If in Deploy mode and no drift exists, complete immediately without redundant mutations
if ($policiesToCreate.Count -eq 0 -and $policiesToUpdate.Count -eq 0) {
    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  [IDEMPOTENT DEPLOY] Live tenant is already in 100% parity! " -ForegroundColor Green
    Write-Host "  Zero PATCH or POST requests required. System in desired state." -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    exit 0
}

# 7. Deployment Confirmation & Rollback Snapshotting
if (-not $Force) {
    $confirm = Read-Host "`nAre you sure you want to deploy these changes to tenant '$($activeContext.TenantId)'? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Deployment aborted by operator." -ForegroundColor Red
        exit 0
    }
}

# Create Mandatory Safety Snapshot before applying changes
$rollbackScript = Join-Path $PSScriptRoot "rollback_policies.ps1"
Write-Host "`nGenerating pre-deployment rollback snapshot..." -ForegroundColor Cyan
try {
    $snapshotId = & $rollbackScript -Action Snapshot
    if (-not $snapshotId) {
        throw "Snapshot execution failed to return a valid snapshot identifier."
    }
} catch {
    Write-Error "[ABORT] Pre-deployment snapshot generation failed: $($_.Exception.Message). Deployment halted to protect tenant."
    exit 1
}

# 8. Execute Deployment Transaction

$deployResult = Invoke-PolicyDeploymentTransaction `
    -ActionsToTake $actionsToTake `
    -SnapshotId $snapshotId `
    -RollbackScript $rollbackScript `
    -ActiveContext $activeContext

if ($deployResult.TransactionState -ne "Completed") {
    Write-Host "`n==========================================================" -ForegroundColor Red
    Write-Host "  DEPLOYMENT TRANSACTION RESULT: $($deployResult.TransactionState) " -ForegroundColor Red
    Write-Host "  Snapshot Baseline: $snapshotId                         " -ForegroundColor White
    Write-Host "==========================================================" -ForegroundColor Red
    exit 1
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  Deployment Successful! All policies synchronized.       " -ForegroundColor Green
Write-Host "  Rollback Snapshot: $snapshotId                         " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
