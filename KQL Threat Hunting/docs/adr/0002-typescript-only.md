# ADR-002: TypeScript-Only Toolchain

## Status
Accepted

## Context
Many detection engineering repositories suffer from "stack drift": using Python for data generation and analysis scripts, Go or Bash for CI tools, and TypeScript for web frontends. This introduces multiple runtime dependencies, fragmented type definitions, and higher setup friction for contributors and interviewers.

## Decision
HuntBook strictly standardizes on a single programming language across the entire repository: **TypeScript 5.x on Node.js (LTS)** organized as a `pnpm` monorepo.

All components will be built in TypeScript:
- `@huntbook/core`: Shared types, hunt schema, ATT&CK taxonomy helpers.
- `@huntbook/cli`: Validation engine, export tools, catalog builder.
- `@huntbook/datagen`: Deterministic synthetic telemetry engine (`@faker-js/faker`).
- `@huntbook/lab-api`: Local Fastify service for executing queries against the Kusto emulator.
- `@huntbook/web`: React 18, Vite, Tailwind CSS, Monaco editor static web UI.

No Python, Go, or shell scripts are permitted for core functionality.

## Consequences
- **Positive:** Single toolchain (`pnpm install && pnpm test`). Universal type sharing between YAML schema, CLI, synthetic datagen, and the React frontend.
- **Negative:** Kusto Python SDK cannot be used; queries against the emulator must use HTTP REST calls or the Node.js `azure-kusto-data` library.

