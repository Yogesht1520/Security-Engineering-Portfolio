import fs from 'node:fs';
import path from 'node:path';

export interface ColumnDefinition {
  name: string;
  type: string;
  description?: string;
}

export interface TableSchema {
  name: string;
  platform: 'sentinel' | 'defender-xdr' | 'both';
  timeColumn: 'TimeGenerated' | 'Timestamp';
  description?: string;
  columns: ColumnDefinition[];
}

export function loadTableSchemas(tablesDir: string): Map<string, TableSchema> {
  const tableMap = new Map<string, TableSchema>();
  if (!fs.existsSync(tablesDir)) {
    return tableMap;
  }

  const files = fs.readdirSync(tablesDir).filter(f => f.endsWith('.json'));
  for (const file of files) {
    const fullPath = path.join(tablesDir, file);
    const content = fs.readFileSync(fullPath, 'utf8');
    const parsed = JSON.parse(content) as TableSchema;
    tableMap.set(parsed.name, parsed);
  }

  return tableMap;
}

