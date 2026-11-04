# Spike B: Kusto Language Service Semantic Analysis

## Objective
Verify that `@kusto/language-service-next` can run inside Node.js to parse KQL queries, validate syntax, and perform semantic type-checking against defined table schemas without requiring an active Azure tenant.

## Findings & Working API
The Microsoft Kusto language engine is compiled via Bridge.NET into JavaScript. In Node.js, it requires executing `bridge.min.js` first to initialize runtime globals, followed by `Kusto.Language.Bridge.min.js`.

### Working TypeScript / JavaScript Pattern:
```javascript
const path = require('path');
const base = require.resolve('@kusto/language-service-next/bridge.min.js');
const dir = path.dirname(base);

require(path.join(dir, 'bridge.min.js'));
require(path.join(dir, 'Kusto.Language.Bridge.min.js'));

const Kusto = globalThis.Kusto;
const Symbols = Kusto.Language.Symbols;
const GlobalState = Kusto.Language.GlobalState;
const KustoCode = Kusto.Language.KustoCode;

// 1. Define Table Schema
const columns = [
  new Symbols.ColumnSymbol('TimeGenerated', Symbols.ScalarTypes.DateTime),
  new Symbols.ColumnSymbol('UserPrincipalName', Symbols.ScalarTypes.String),
  new Symbols.ColumnSymbol('IPAddress', Symbols.ScalarTypes.String),
  new Symbols.ColumnSymbol('ResultType', Symbols.ScalarTypes.String)
];
const table = new Symbols.TableSymbol.$ctor4('SigninLogs', columns);

// 2. Attach to Database & Global State
const db = new Symbols.DatabaseSymbol.ctor('HuntBookDB', [table]);
const globals = GlobalState.Default.WithDatabase(db);

// 3. Analyze Query
const query = `
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "50126"
| summarize FailedUsers = dcount(UserPrincipalName) by IPAddress
| where FailedUsers >= 10
`;

const parsed = KustoCode.ParseAndAnalyze(query, globals);
const diagnostics = parsed.GetDiagnostics();

if (diagnostics.Count === 0) {
  console.log('Query is syntactically and semantically valid.');
} else {
  for (let i = 0; i < diagnostics.Count; i++) {
    const diag = diagnostics.getItem(i);
    console.error(`[${diag.Severity}] ${diag.Message}`);
  }
}
```

## Validation Outcome
- **Valid Query:** Diagnostics count = 0.
- **Invalid Column / Table:** Emits diagnostic error: `The name '<Field>' does not refer to any known column, table, variable or function.`
- **Syntax Error (e.g. malformed operator):** Emits syntax error diagnostic.
- **Result:** Fully proven. Can be wrapped cleanly into `@huntbook/core` for CI validation and CLI checks.

