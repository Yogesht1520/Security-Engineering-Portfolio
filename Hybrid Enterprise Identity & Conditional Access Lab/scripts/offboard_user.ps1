<#
.SYNOPSIS
    Automated User Offboarding (Leaver Lifecycle Entry Point).
.DESCRIPTION
    Forwards to the production-grade Leaver engine in identity-lifecycle/leaver/offboard_user.ps1
    with fail-closed break-glass protection, PIM role revocation, session termination, and audit logging.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,
    [string]$TicketId = "HR-TERM-MANUAL",
    [switch]$DeviceCode
)

$targetScript = Join-Path $PSScriptRoot "..\identity-lifecycle\leaver\offboard_user.ps1"
& $targetScript @PSBoundParameters
