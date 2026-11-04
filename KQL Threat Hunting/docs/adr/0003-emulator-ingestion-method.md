# ADR-003: Local Emulator Ingestion Method

## Status
Accepted

## Context
The Kusto emulator (`kustainer-linux`) must be provisioned with table schemas and synthetic attack/baseline datasets before tests can be executed. We evaluated three methods:
1. **Mounted Volume Ingestion (`.ingest into table ...` from container filesystem)**
2. **Inline Ingestion via KQL management commands (`.ingest inline into table <Name> <| ...`)**
3. **HTTP REST / Ingestion SDK streaming ingestion**

## Decision
We standardize on **Inline Ingestion via Kusto Management Commands (`.ingest inline`)** and **JSON table definitions**:

1. Schema creation: The runner reads `schemas/tables/<Table>.json` and issues:
   ```kql
   .create-merge table <TableName> (Col1:type, Col2:type, ...)
   ```
2. Data population: For synthetic datasets (typically 10 to 500 rows per scenario), the runner serializes events into CSV/TSV format and sends the command:
   ```kql
   .ingest inline into table <TableName> <|
   value1,value2,value3
   value4,value5,value6
   ```
3. For larger baselines (> 1,000 rows), datasets are written to NDJSON and ingested via volume-mapped paths or chunked inline commands.

## Consequences
- **Positive:** Zero external storage dependencies (no Azure Blob Storage required). Works natively across local environments and GitHub Actions CI.
- **Negative:** Inline ingestion has a per-command payload limit (~several MBs), which is more than sufficient for unit test scenario datasets.

