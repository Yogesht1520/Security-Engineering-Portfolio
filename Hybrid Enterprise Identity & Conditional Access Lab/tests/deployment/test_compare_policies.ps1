# Test Drift Detection & Canonical Normalization Logic
$compareScript = Join-Path $PSScriptRoot "..\..\scripts\deployment\compare_policies.ps1"
$engineScript  = Join-Path $PSScriptRoot "..\..\scripts\deployment\deployment_engine.ps1"
. $engineScript

Write-Host "Running Drift Detection & Canonical Normalization Tests..." -ForegroundColor Cyan

# Test Case 1: Identical policies (No drift)
$policyA = [PSCustomObject]@{
    displayName = "CAP-001: Test"
    state = "enabledForReportingButNotEnforced"
    conditions = [PSCustomObject]@{ users = [PSCustomObject]@{ includeUsers = @("All") } }
    grantControls = [PSCustomObject]@{ operator = "OR"; builtInControls = @("block") }
    sessionControls = [PSCustomObject]@{}
}
$policyB = [PSCustomObject]@{
    id = "guid-12345"
    displayName = "CAP-001: Test"
    state = "enabledForReportingButNotEnforced"
    createdDateTime = "2026-01-01T00:00:00Z"
    conditions = [PSCustomObject]@{ users = [PSCustomObject]@{ includeUsers = @("All") } }
    grantControls = [PSCustomObject]@{ operator = "OR"; builtInControls = @("block") }
    sessionControls = [PSCustomObject]@{}
}

$res1 = & $compareScript -LocalPolicy $policyA -LivePolicy $policyB
if ($res1.HasDrift -eq $false) {
    Write-Host "  [PASS] Test 1: Identical policies correctly report NO drift." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 1: Unexpected drift detected."
    exit 1
}

# Test Case 2: State drift (Desired Report-only, Live is Enabled)
$policyC = [PSCustomObject]@{
    id = "guid-12345"
    displayName = "CAP-001: Test"
    state = "enabled"
    conditions = [PSCustomObject]@{ users = [PSCustomObject]@{ includeUsers = @("All") } }
    grantControls = [PSCustomObject]@{ operator = "OR"; builtInControls = @("block") }
    sessionControls = [PSCustomObject]@{}
}

$res2 = & $compareScript -LocalPolicy $policyA -LivePolicy $policyC
if ($res2.HasDrift -eq $true) {
    Write-Host "  [PASS] Test 2: State drift detected successfully (Expected Report-only, Live Enabled)." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 2: Failed to detect state drift."
    exit 1
}

# Test Case 3: Canonical Normalization - Array Ordering Equivalence
$policyOrder1 = [PSCustomObject]@{
    displayName = "CAP-002: Reordered Array"
    conditions = [PSCustomObject]@{
        users = [PSCustomObject]@{
            includeUsers  = @("user-gamma", "user-alpha", "user-beta")
            excludeGroups = @("grp-z", "grp-a")
        }
    }
}
$policyOrder2 = [PSCustomObject]@{
    displayName = "CAP-002: Reordered Array"
    conditions = [PSCustomObject]@{
        users = [PSCustomObject]@{
            includeUsers  = @("user-alpha", "user-beta", "user-gamma")
            excludeGroups = @("grp-a", "grp-z")
        }
    }
}

$diffOrder = Compare-CanonicalPolicyParity -LivePolicy $policyOrder1 -SnapshotPolicy $policyOrder2
if ($diffOrder.Count -eq 0) {
    Write-Host "  [PASS] Test 3: Array reordering edge case normalized to zero false drift." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 3: Array reordering caused false drift ($($diffOrder -join '; '))."
    exit 1
}

# Test Case 4: Canonical Normalization - Key Ordering Equivalence
$policyKeys1 = [PSCustomObject]@{
    zKey = "last"
    aKey = "first"
    mKey = [PSCustomObject]@{ nestedZ = 2; nestedA = 1 }
}
$policyKeys2 = [PSCustomObject]@{
    aKey = "first"
    mKey = [PSCustomObject]@{ nestedA = 1; nestedZ = 2 }
    zKey = "last"
}

$normKeys1 = Get-CanonicalNormalizedPolicy -Policy $policyKeys1
$normKeys2 = Get-CanonicalNormalizedPolicy -Policy $policyKeys2
if ($normKeys1 -eq $normKeys2) {
    Write-Host "  [PASS] Test 4: Object key ordering normalized to identical canonical JSON representation." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 4: Key ordering produced differing canonical representations."
    exit 1
}

# Test Case 5: Canonical Normalization - Server Volatile Metadata Stripping
$policyMeta = [PSCustomObject]@{
    id                = "volatile-guid-999"
    "@odata.context"  = "https://graph.microsoft.com/v1.0/$metadata"
    "@odata.etag"     = "W/`"XYZ123`""
    createdDateTime   = "2026-05-01T12:00:00Z"
    modifiedDateTime  = "2026-05-02T14:30:00Z"
    templateId        = "template-abc"
    displayName       = "CAP-003: Clean Metadata"
    state             = "enabledForReportingButNotEnforced"
}
$policyClean = [PSCustomObject]@{
    displayName       = "CAP-003: Clean Metadata"
    state             = "enabledForReportingButNotEnforced"
}

$diffMeta = Compare-CanonicalPolicyParity -LivePolicy $policyMeta -SnapshotPolicy $policyClean
if ($diffMeta.Count -eq 0) {
    Write-Host "  [PASS] Test 5: Volatile server metadata (@odata, id, timestamps) stripped cleanly." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 5: Metadata stripping failed ($($diffMeta -join '; '))."
    exit 1
}

# Test Case 6: Canonical Normalization - Null vs Missing Property Handling
$policyNull1 = [PSCustomObject]@{
    displayName = "CAP-004: Null Handling"
    conditions  = [PSCustomObject]@{
        users = [PSCustomObject]@{
            includeUsers = @("All")
            excludeUsers = $null
        }
    }
}
$policyNull2 = [PSCustomObject]@{
    displayName = "CAP-004: Null Handling"
    conditions  = [PSCustomObject]@{
        users = [PSCustomObject]@{
            includeUsers = @("All")
        }
    }
}
$policyNull3 = [PSCustomObject]@{
    displayName = "CAP-004: Null Handling"
    conditions  = [PSCustomObject]@{
        users = [PSCustomObject]@{
            includeUsers = @("All")
            excludeUsers = @("user-guest")
        }
    }
}

# 6a. Explicit null vs omitted property normalizes to identical canonical state (no false drift)
$diffNullEquiv = Compare-CanonicalPolicyParity -LivePolicy $policyNull1 -SnapshotPolicy $policyNull2
if ($diffNullEquiv.Count -eq 0) {
    Write-Host "  [PASS] Test 6a: Explicit null vs omitted property correctly treated as semantically identical (zero false drift)." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 6a: Explicit null vs omitted caused false drift ($($diffNullEquiv -join '; '))."
    exit 1
}

# 6b. Null/omitted property vs actual value correctly detected as real drift
$diffNullReal = @(Compare-CanonicalPolicyParity -LivePolicy $policyNull1 -SnapshotPolicy $policyNull3)
if ($diffNullReal.Count -gt 0 -and $diffNullReal[0] -match "excludeUsers") {
    Write-Host "  [PASS] Test 6b: Null/omitted property vs actual value correctly flagged as real configuration drift." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 6b: Real difference between null and value was not detected."
    exit 1
}

# Test Case 7: Canonical Normalization - Deep Field-Level Diff Reporting
$policyDiff1 = [PSCustomObject]@{
    displayName   = "CAP-005: Deep Diff"
    grantControls = [PSCustomObject]@{
        operator         = "OR"
        builtInControls  = @("mfa")
        termsOfUse       = @("tou-standard")
    }
}
$policyDiff2 = [PSCustomObject]@{
    displayName   = "CAP-005: Deep Diff"
    grantControls = [PSCustomObject]@{
        operator         = "OR"
        builtInControls  = @("mfa")
        termsOfUse       = @("tou-updated-2026")
    }
}

$diffDeep = @(Compare-CanonicalPolicyParity -LivePolicy $policyDiff1 -SnapshotPolicy $policyDiff2)
if ($diffDeep.Count -eq 1 -and $diffDeep[0] -match "termsOfUse") {
    Write-Host "  [PASS] Test 7: Deep field-level difference reported with exact property path." -ForegroundColor Green
} else {
    Write-Error "  [FAIL] Test 7: Deep field difference not correctly isolated ($($diffDeep -join '; '))."
    exit 1
}

Write-Host "`nAll 7 drift detection & canonical normalization tests passed!" -ForegroundColor Green
