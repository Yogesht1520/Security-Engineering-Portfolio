<#
.SYNOPSIS
    Declarative Identity-as-Code Pipeline Entry Point.
.DESCRIPTION
    Unified entry point forwarding to the production-grade deployment engine in scripts/deployment/deploy_ca_policies.ps1.
#>

param (
    [string]$PoliciesPath = "$PSScriptRoot\..\policies",
    [switch]$ValidateOnly,
    [switch]$Plan,
    [switch]$Deploy,
    [string]$Environment = "Lab",
    [string]$PolicyId,
    [switch]$DeviceCode,
    [switch]$Force
)

$targetScript = Join-Path $PSScriptRoot "deployment\deploy_ca_policies.ps1"
& $targetScript @PSBoundParameters
