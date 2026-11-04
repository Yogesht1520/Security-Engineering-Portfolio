const path = require('path');
const base = path.resolve(__dirname, '../node_modules/@kusto/language-service-next');
require(path.join(base, 'bridge.min.js'));
require(path.join(base, 'Kusto.Language.Bridge.min.js'));

const Kusto = globalThis.Kusto;
const Symbols = Kusto.Language.Symbols;
const GlobalState = Kusto.Language.GlobalState;
const KustoCode = Kusto.Language.KustoCode;

console.log('--- Testing TableSymbol and DatabaseSymbol ---');

const columns = [
  new Symbols.ColumnSymbol('TimeGenerated', Symbols.ScalarTypes.DateTime),
  new Symbols.ColumnSymbol('UserPrincipalName', Symbols.ScalarTypes.String),
  new Symbols.ColumnSymbol('IPAddress', Symbols.ScalarTypes.String),
  new Symbols.ColumnSymbol('ResultType', Symbols.ScalarTypes.String)
];
const signinTable = new Symbols.TableSymbol.$ctor4('SigninLogs', columns);
const db = new Symbols.DatabaseSymbol.ctor('TestDB', [signinTable]);
const globals = GlobalState.Default.WithDatabase(db);

const validKql = `
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "50126"
| summarize FailedCount = count() by IPAddress
| where FailedCount >= 5
`;
const codeValid = KustoCode.ParseAndAnalyze(validKql, globals);
const diagValid = codeValid.GetDiagnostics();
console.log('Valid query diagnostics count (should be 0):', diagValid.Count);
for (let i = 0; i < diagValid.Count; i++) {
  console.log('  Unexpected Diagnostic:', diagValid.getItem(i).Message);
}

const badKql = `
SigninLogs
| where TimeGenerated > ago(1d)
| where UnknownColumn == "invalid"
`;
const codeBad = KustoCode.ParseAndAnalyze(badKql, globals);
const diagBad = codeBad.GetDiagnostics();
console.log('Bad query diagnostics count (should be 1):', diagBad.Count);
for (let i = 0; i < diagBad.Count; i++) {
  console.log(`  Expected Diagnostic ${i+1}:`, diagBad.getItem(i).Message);
}
