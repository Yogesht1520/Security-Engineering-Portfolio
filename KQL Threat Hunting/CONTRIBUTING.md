# Contributing to HuntBook

Thank you for contributing to HuntBook! We welcome community contributions to expand our Detection-as-Code threat hunting library for Microsoft Defender XDR and Sentinel.

## Development Workflow

1. **Prerequisites:**
   - Node.js 22 LTS or newer
   - `pnpm` (install via `npm install -g pnpm`)
   - Docker Desktop (optional, for local Kusto emulator)

2. **Setup:**
   ```bash
   pnpm install
   pnpm build
   pnpm test
   ```

3. **Authoring a New Hunt:**
   - Create your `.kql` file under the appropriate directory in `hunts/` (e.g. `hunts/endpoint/`, `hunts/identity/`, `hunts/cloud/`).
   - Create the corresponding `.hunt.yml` file with full metadata matching `schemas/hunt.schema.json`.
   - Verify that your query includes partition pruning on line 1 (`where TimeGenerated > ago(...)` or `where Timestamp > ago(...)`).

4. **Running Validation:**
   ```bash
   node packages/cli/dist/cli.js validate
   ```
   All hunts must pass both JSON Schema validation and KQL AST semantic type checking against target table schemas.

5. **Running Tests & Building:**
   ```bash
   node packages/cli/dist/cli.js test
   node packages/cli/dist/cli.js build
   ```

6. **Submitting a Pull Request:**
   - Ensure `pnpm test` and `huntbook validate` pass with zero errors.
   - Adhere to the **Honesty Rule**: hunts must be marked `synthetic` or `syntax` based on verified test evidence.

