# Sanitized Live Tenant State & Telemetry Evidence

This directory contains offline, sanitized telemetry and state exports generated directly from the live Microsoft Entra ID tenant (`<LAB_DOMAIN>` / Tenant ID: `<REDACTED_TENANT_ID>`) during verification.

## Evidence Artifacts

| File | Graph API Resource | Purpose & Verification Scope |
| :--- | :--- | :--- |
| `conditional-access-policies.json` | `/identity/conditionalAccess/policies` | Proves all 11 declarative policies (`CAP-001` through `CAP-012`) are active in the live tenant in `Report-only` staging mode. |
| `named-locations.json` | `/identity/conditionalAccess/namedLocations` | Proves `Corporate Trusted HQ` (trusted IP CIDR ranges) and `Blocked Geographies` are provisioned and evaluated by `CAP-001`. |
| `pim-eligibility-schedules.json` | `/roleManagement/directory/roleEligibilityScheduleInstances` | Verifies Zero Standing Access (ZSA) with JIT eligibility for `Conditional Access Administrator` and `Security Administrator`. |
| `privileged-role-inventory.md` | `/roleManagement/directory/roleAssignments` | Itemized Zero Standing Access audit breakdown explaining the 2 permanent Break-Glass accounts vs 0 standing workforce roles. |
| `sign-in-telemetry-receipt.json` | `/auditLogs/signIns` | Live sign-in event receipts demonstrating `reportOnlySuccess` evaluation without user impact. |

> [!NOTE]
> All personal identifiers and live tenant IDs have been sanitized in conformance with enterprise repository hygiene requirements (`<LAB_DOMAIN>`, `<REDACTED_TENANT_ID>`).
