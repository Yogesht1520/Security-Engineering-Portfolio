# Project Context: HuntBook

> **Working name:** HuntBook (`kql-threat-hunting`)  
> **Owner:** Yogesh Thakur · **Status:** v1.0.0 Complete · **Current Phase:** Production Polish & Review Refinements  
> This file is the authoritative project context and rules. If anything elsewhere conflicts with it, this file wins.

---

## Why this project exists
- Close the owner's main resume gap for Microsoft security roles: hands-on KQL and Defender/Sentinel telemetry.
- Be **explainable in an interview**: the owner must be able to justify every line.
- Show engineering discipline (tests, CI, docs), not just a pile of queries.

## In scope
- 30 original hunts across identity, endpoint, persistence, lateral movement, email, cloud, ransomware, and C2.
- Metadata schema, validator, synthetic data generator, test runner, catalog and coverage builder, Sentinel analytics rule exporter.
- Static web UI (Overview, Catalog, Hunt Detail, Coverage, Scenarios, Validation, About).
- Optional local Lab mode (Docker Compose) for running hunts against synthetic data.
- Documentation: architecture, ADRs, hunt notes, demo script, interview FAQ.

## Out of scope (do not build or propose without an ADR)
Real or customer data, user accounts and logins, hosted backend or database, real-time ingestion, ML detection, paid services, offensive tooling, Defender custom detection export (v1), mobile app, integration with the owner's earlier projects (deferred).

## Locked stack
The stack in Section 5 of `HUNTBOOK_PLAN.md` is final. No new library, language, or service without an approved ADR. Python, databases, hosted services, and paid tiers are not allowed.

## Glossary
| Term | Meaning here |
|---|---|
| **Hunt** | A KQL query written from a hypothesis to find suspicious behavior (produces leads, not necessarily alerts) |
| **Detection rule** | A hunt promoted to an automated alert with tuning |
| **Hunt file** | `<TechniqueID>-<slug>.kql` plus `<same>.hunt.yml` |
| **Scenario** | A short synthetic attack story on top of benign baseline data |
| **Baseline** | Benign synthetic telemetry that creates realistic false-positive noise |
| **Validation level** | `syntax`, `synthetic` or `tenant`; never claim more than was done |
| **Catalog** | Generated `catalog.json`, the only input to the web UI |
| **Lab** | Optional local runtime: emulator plus Lab API |

## Conventions
- **IDs:** `HB-<AREA>-<NNN>` where AREA is `ID, EP, PS, LM, EM, CL, RW, C2`.
- **Files:** kebab-case, technique ID first, under `hunts/<area>/`.
- **Time column:** Defender tables use `Timestamp`; Sentinel tables use `TimeGenerated`. Always declare it in the YAML.
- **KQL style:** parameters as `let` statements at the top, comment header, one operator per line, readable over clever.
- **Data:** synthetic only; reserved ranges (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`), `contoso.test`, `*.example`.
- **Commits:** Conventional Commits (`feat(hunts): add HB-ID-001`). `main` is protected; work on short-lived branches and PRs.
- **Generated files:** (`catalog.json`, `coverage.json`, site output) are never edited by hand.

## Definition of Done for any task
1. Lint, `huntbook validate`, and tests pass locally and in CI.
2. Docs touched by the change are updated.
3. "Current state" (below) is updated.
4. For hunts: the per-hunt checklist is satisfied.

## Rules for AI agents (and for the owner when tired)
1. Read this section first. State the **phase and task** you are working on.
2. Do one task at a time. Do not jump ahead to later phases.
3. Never expand scope. If an idea is outside "In scope", write it to `docs/ideas.md` and continue.
4. Never add dependencies outside Section 5. Propose an ADR instead.
5. Do not invent Microsoft table columns, API behavior or tool options. Check official docs or Phase 0 spike notes; otherwise mark `TODO(verify)`.
6. Do not fabricate results, test outcomes or metrics. If a command was not run, say so.
7. No real data, no secrets, no copied third-party queries. Credit any reference.
8. Every new hunt follows Section 7.1 and the 11.1 checklist; never mark a validation level higher than what was tested.
9. Prefer explainability: a reader should understand what a query does and why.
10. When unsure about scope, stack or intent, ask the owner before building.

## Current state
| Field | Value |
|---|---|
| **Current phase** | v1.0.0 Production Complete (All Phases 0 - 6 Complete) |
| **Last completed task** | Authored all 30 hunts, generated ATT&CK Navigator v4.5 layer, Sentinel exporter, 60 synthetic tests passing, Web SOC console built, and completed Interview Kit (demo script, interview FAQ, architecture, 3 hunt notes) |
| **Next task** | Project maintenance and community contributions |
| **Hunts authored** | 30 / 30 |
| **Validation levels reached** | `synthetic` (30 / 30) |
| **Known issues** | None |
| **Open decisions** | None |
