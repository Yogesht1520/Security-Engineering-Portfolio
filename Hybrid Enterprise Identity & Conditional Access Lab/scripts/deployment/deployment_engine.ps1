<#
.SYNOPSIS
    Declarative Policy Deployment Engine & Canonical Comparison Subsystem for Microsoft Entra Conditional Access.
.DESCRIPTION
    Provides reusable deployment transaction orchestration and canonical policy normalization:
    - Invoke-PolicyDeploymentTransaction: Core transactional orchestrator with per-policy tracking,
      ambiguous write recovery, and automated rollback execution.
    - Get-CanonicalNormalizedPolicy: Recursively canonicalizes policy objects, sorting keys and
      unordered value arrays, stripping server-generated metadata.
    - Compare-CanonicalPolicyParity: Deep property-by-property comparison returning explicit field-level diffs.
#>

function Get-CanonicalNormalizedPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $Policy
    )

    if ($null -eq $Policy) { return $null }

    # If string JSON, convert to PSObject first
    if ($Policy -is [string]) {
        try {
            $Policy = $Policy | ConvertFrom-Json
        } catch {
            return $Policy
        }
    }

    # Recursive normalization helper
    function ConvertTo-NormalizedElement ($elem, [string]$parentKey = "") {
        if ($null -eq $elem) { return $null }

        # Unordered collection keys where array item order is semantically irrelevant in Entra ID
        $unorderedArrayKeys = @(
            "includeUsers", "excludeUsers", "includeGroups", "excludeGroups",
            "includeRoles", "excludeRoles", "includeApplications", "excludeApplications",
            "includeUserActions", "includeLocations", "excludeLocations", "clientAppTypes",
            "builtInControls", "signInRiskLevels", "userRiskLevels", "platforms", "values"
        )

        # Handle Array / IList
        if ($elem -is [System.Collections.IEnumerable] -and $elem -isnot [string] -and $elem -isnot [System.Collections.IDictionary]) {
            $normalizedList = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $elem) {
                $normalizedList.Add((ConvertTo-NormalizedElement $item $parentKey))
            }

            # If this array belongs to an unordered set and contains scalar values, sort ordinally
            if ($unorderedArrayKeys -contains $parentKey -and $normalizedList.Count -gt 1) {
                $allScalar = $true
                foreach ($val in $normalizedList) {
                    if ($val -is [System.Collections.IDictionary] -or $val -is [PSCustomObject]) {
                        $allScalar = $false
                        break
                    }
                }
                if ($allScalar) {
                    $sorted = @($normalizedList | Sort-Object { [string]$_ })
                    return ,$sorted
                }
            }
            return ,$normalizedList.ToArray()
        }

        # Handle Strings (Trim)
        if ($elem -is [string]) {
            return $elem.Trim()
        }

        # Handle Primitives & Value Types (bool, int, datetime, etc.)
        if ($elem -is [System.ValueType]) {
            return $elem
        }

        # Handle Object / PSObject / Dictionary
        if ($elem -is [System.Collections.IDictionary] -or $elem -is [PSCustomObject] -or ($elem.PSObject -and $elem.PSObject.Properties)) {
            $sortedDict = [ordered]@{}
            $props = if ($elem -is [System.Collections.IDictionary]) {
                @($elem.Keys | Sort-Object { [string]$_ })
            } else {
                @($elem.PSObject.Properties | Select-Object -ExpandProperty Name | Sort-Object { [string]$_ })
            }

            $volatileMetadataProps = @(
                "id", "createdDateTime", "modifiedDateTime", "@odata.context",
                "@odata.nextLink", "@odata.etag", "templateId"
            )

            foreach ($propName in $props) {
                if ($volatileMetadataProps -contains $propName) {
                    continue
                }
                $val = if ($elem -is [System.Collections.IDictionary]) { $elem[$propName] } else { $elem.$propName }
                if ($null -ne $val) {
                    $sortedDict[$propName] = ConvertTo-NormalizedElement $val $propName
                }
            }
            return $sortedDict
        }

        return $elem
    }

    $canonicalDict = ConvertTo-NormalizedElement $Policy
    return ($canonicalDict | ConvertTo-Json -Depth 20 -Compress)
}

function Compare-CanonicalPolicyParity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $LivePolicy,
        [Parameter(Mandatory=$true)]
        $SnapshotPolicy
    )

    $differences = [System.Collections.Generic.List[string]]::new()

    $liveNormJson = Get-CanonicalNormalizedPolicy -Policy $LivePolicy
    $snapNormJson = Get-CanonicalNormalizedPolicy -Policy $SnapshotPolicy

    if ($liveNormJson -eq $snapNormJson) {
        return @()
    }

    $liveObj = $liveNormJson | ConvertFrom-Json
    $snapObj = $snapNormJson | ConvertFrom-Json

    # Recursive field-by-field diff
    function Compare-FieldLevel ($path, $liveVal, $snapVal) {
        if ($null -eq $liveVal -and $null -ne $snapVal) {
            $differences.Add("${path}: Missing in live tenant (Expected: '$($snapVal | ConvertTo-Json -Depth 5 -Compress)')")
            return
        }
        if ($null -ne $liveVal -and $null -eq $snapVal) {
            $differences.Add("${path}: Extra in live tenant (Actual: '$($liveVal | ConvertTo-Json -Depth 5 -Compress)')")
            return
        }

        $liveJson = $liveVal | ConvertTo-Json -Depth 10 -Compress
        $snapJson = $snapVal | ConvertTo-Json -Depth 10 -Compress

        if ($liveJson -ne $snapJson) {
            $isObjLive = ($liveVal -is [PSCustomObject] -or $liveVal -is [System.Collections.IDictionary])
            $isObjSnap = ($snapVal -is [PSCustomObject] -or $snapVal -is [System.Collections.IDictionary])

            if ($isObjLive -and $isObjSnap) {
                $allKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                if ($liveVal.PSObject) { foreach ($p in $liveVal.PSObject.Properties.Name) { $allKeys.Add($p) | Out-Null } }
                if ($snapVal.PSObject) { foreach ($p in $snapVal.PSObject.Properties.Name) { $allKeys.Add($p) | Out-Null } }

                foreach ($k in ($allKeys | Sort-Object)) {
                    $subPath = if ($path) { "$path.$k" } else { $k }
                    $lv = $liveVal.$k
                    $sv = $snapVal.$k
                    Compare-FieldLevel $subPath $lv $sv
                }
            } else {
                $differences.Add("${path}: Expected '$snapJson', Actual '$liveJson'")
            }
        }
    }

    Compare-FieldLevel "" $liveObj $snapObj
    return @($differences)
}

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
                        $diffs = Compare-CanonicalPolicyParity -LivePolicy $livePol -SnapshotPolicy $snapshotFile
                        if ($diffs.Count -gt 0) {
                            $mutationsApplied++
                            Write-Warning "  -> [AMBIGUOUS WRITE DETECTED] Server applied update prior to connection loss! Live state differs from pre-deployment snapshot ($($diffs.Count) field(s) drifted). Flagged for mandatory rollback."
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

    # Automatic In-Flight Rollback & Transaction State Machine
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
            $transactionState = "FailedAndClean"
            Write-Host "Zero tenant mutations were applied prior to failure. Snapshot baseline is intact." -ForegroundColor Green
        }
    }

    # Persist Formal Deployment Transaction Receipt
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
