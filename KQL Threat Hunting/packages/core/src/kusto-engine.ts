import { createRequire } from 'node:module';
import path from 'node:path';
import type { TableSchema } from './schema-loader.js';

const require = createRequire(import.meta.url);

// Initialize Bridge and Kusto Language runtime
let isInitialized = false;
let KustoInstance: any = null;

function ensureKustoInitialized() {
  if (isInitialized && KustoInstance) return KustoInstance;

  try {
    const bridgePath = require.resolve('@kusto/language-service-next/bridge.min.js');
    const baseDir = path.dirname(bridgePath);

    require(path.join(baseDir, 'bridge.min.js'));
    require(path.join(baseDir, 'Kusto.Language.Bridge.min.js'));

    KustoInstance = (globalThis as any).Kusto;
    isInitialized = true;
    return KustoInstance;
  } catch (err) {
    throw new Error(`Failed to initialize Kusto Language Engine: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export function validateKql(
  kqlContent: string,
  tableSchemas: Map<string, TableSchema>
): { valid: boolean; errors: string[] } {
  const Kusto = ensureKustoInitialized();
  const Symbols = Kusto.Language.Symbols;
  const GlobalState = Kusto.Language.GlobalState;
  const KustoCode = Kusto.Language.KustoCode;

  // Build table symbols from schemas
  const tableSymbols: any[] = [];
  for (const [tableName, schema] of tableSchemas.entries()) {
    const colSymbols = schema.columns.map(col => {
      let scalarType = Symbols.ScalarTypes.String;
      switch (col.type.toLowerCase()) {
        case 'datetime':
          scalarType = Symbols.ScalarTypes.DateTime;
          break;
        case 'dynamic':
          scalarType = Symbols.ScalarTypes.Dynamic;
          break;
        case 'int':
        case 'long':
          scalarType = Symbols.ScalarTypes.Long;
          break;
        case 'real':
        case 'double':
          scalarType = Symbols.ScalarTypes.Real;
          break;
        case 'bool':
        case 'boolean':
          scalarType = Symbols.ScalarTypes.Bool;
          break;
        case 'guid':
          scalarType = Symbols.ScalarTypes.Guid;
          break;
        case 'timespan':
          scalarType = Symbols.ScalarTypes.TimeSpan;
          break;
        default:
          scalarType = Symbols.ScalarTypes.String;
      }
      return new Symbols.ColumnSymbol(col.name, scalarType);
    });

    const tableSymbol = new Symbols.TableSymbol.$ctor4(tableName, colSymbols);
    tableSymbols.push(tableSymbol);
  }

  const db = new Symbols.DatabaseSymbol.ctor('HuntBookDB', tableSymbols);
  const globals = GlobalState.Default.WithDatabase(db);

  const parsed = KustoCode.ParseAndAnalyze(kqlContent, globals);
  const diagnostics = parsed.GetDiagnostics();

  const errors: string[] = [];
  if (diagnostics.Count > 0) {
    for (let i = 0; i < diagnostics.Count; i++) {
      const diag = diagnostics.getItem(i);
      errors.push(`[${diag.Severity}] ${diag.Message}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

