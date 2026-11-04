const fs = require('fs');
const path = require('path');
const base = path.resolve(__dirname, '../node_modules/@kusto/language-service-next');
require(path.join(base, 'bridge.min.js'));
require(path.join(base, 'Kusto.Language.Bridge.min.js'));

const Kusto = globalThis.Kusto;
const Symbols = Kusto.Language.Symbols;
const GlobalState = Kusto.Language.GlobalState;
const KustoCode = Kusto.Language.KustoCode;

const schemaJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../../schemas/tables/SigninLogs.json'), 'utf8'));
const cols = schemaJson.columns.map(c => {
  let type = Symbols.ScalarTypes.String;
  if (c.type === 'datetime') type = Symbols.ScalarTypes.DateTime;
  if (c.type === 'dynamic') type = Symbols.ScalarTypes.Dynamic;
  if (c.type === 'int' || c.type === 'long') type = Symbols.ScalarTypes.Long;
  return new Symbols.ColumnSymbol(c.name, type);
});

const table = new Symbols.TableSymbol.$ctor4('SigninLogs', cols);
const db = new Symbols.DatabaseSymbol.ctor('HuntBookDB', [table]);
const globals = GlobalState.Default.WithDatabase(db);

const kqlPath = path.resolve(__dirname, '../../../hunts/identity/T1110.003-password-spray.kql');
const kqlContent = fs.readFileSync(kqlPath, 'utf8');
const parsed = KustoCode.ParseAndAnalyze(kqlContent, globals);
const diags = parsed.GetDiagnostics();

console.log('Diagnostics count for HB-ID-001:', diags.Count);
if (diags.Count === 0) {
  console.log('SUCCESS: HB-ID-001 passed AST & semantic type checking against SigninLogs schema!');
} else {
  for (let i = 0; i < diags.Count; i++) {
    console.error('Diag:', diags.getItem(i).Message);
  }
}

