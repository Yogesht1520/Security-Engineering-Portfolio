<#
.SYNOPSIS
    Reusable Microsoft Entra ID Live Tenant Evidence Sanitizer Engine.
.DESCRIPTION
    Provides deterministic data masking and sanitization for JSON payloads exported from
    live Microsoft Graph endpoints. Sanitizes tenant IDs, directory object GUIDs, UPNs,
    emails, IPv4 addresses, full/compressed IPv6 addresses, and IPv4-mapped IPv6 addresses.
#>

function ConvertTo-SanitizedJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $InputObject,

        [Parameter(Mandatory=$false)]
        [string]$TenantIdToRedact = $null
    )

    $json = $InputObject | ConvertTo-Json -Depth 20

    # 1. Redact specific tenant ID if provided
    if (-not [string]::IsNullOrWhiteSpace($TenantIdToRedact)) {
        $json = $json -replace [regex]::Escape($TenantIdToRedact), "<REDACTED_TENANT_ID>"
    }

    # 2. Redact all email addresses and UPNs (including onmicrosoft.com, custom domains, external domains)
    $json = $json -replace '(?i)\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', '<REDACTED_USER>@<LAB_DOMAIN>'

    # 3. Redact IPv4-mapped IPv6 addresses (e.g., ::ffff:192.0.2.128)
    $json = $json -replace '(?i)(?:^|(?<=[^a-f0-9:]))::ffff:(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?=[^a-f0-9:]|$)', '<REDACTED_IPV4_MAPPED_IPV6>'

    # 4. Redact full and compressed IPv6 addresses (e.g., 2001:db8::1, ::1, 2001:0db8:85a3::8a2e:0370:7334)
    $ipv6Pattern = '(?i)(?:^|(?<=[^a-f0-9:]))(?>([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|::([0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}|[0-9a-f]{1,4}::([0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})(?=[^a-f0-9:]|$)'
    $json = $json -replace $ipv6Pattern, '<REDACTED_IPV6>'

    # 5. Redact standard IPv4 addresses with optional CIDR mask (e.g., 198.51.100.24, 10.200.1.0/24)
    $json = $json -replace '\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b', '<REDACTED_IP>'

    # 6. Redact all standard 36-character GUIDs (object IDs, user IDs, group IDs, roleDefinitionIds, directoryScopeIds)
    $json = $json -replace '\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', '<REDACTED_GUID>'

    return $json
}
