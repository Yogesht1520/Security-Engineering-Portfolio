# ADR-001: Kusto Emulator Container Exception

## Status
Accepted

## Context
HuntBook needs a local, free, zero-tenant mechanism to execute KQL queries against synthetic telemetry so that "it works" is verified with objective test assertions rather than claims.

While our hard constraint specifies open source tools wherever possible, KQL's execution engine is proprietary to Microsoft. There is no fully open-source KQL execution engine with parity to Azure Data Explorer (ADX) / Microsoft Defender XDR / Sentinel.

Microsoft provides an official, free-to-use container image:
`mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`

## Decision
We approve a single, documented exception to the open-source rule for the Kusto emulator container image (`kustainer-linux`).

1. The emulator is free of charge and requires only `ACCEPT_EULA=Y`.
2. It runs locally via Docker Compose on port `8080`.
3. If Docker is unavailable or the user is on a resource-constrained system, the project gracefully degrades to `syntax` validation using `@kusto/language-service-next` (which is open source MIT).

## Consequences
- **Positive:** Enables local execution of real KQL queries with exact Kusto semantics. Tests assert row counts and column values deterministically.
- **Negative:** Requires Docker with ~4GB RAM allocated when running synthetic tests.
- **Fallback:** If the container cannot be run, `validation_level` remains at `syntax`, which is transparently recorded in metadata.

