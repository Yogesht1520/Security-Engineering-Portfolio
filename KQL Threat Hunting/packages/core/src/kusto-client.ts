export interface KustoQueryResponse {
  Tables: Array<{
    TableName: string;
    Columns: Array<{ ColumnName: string; DataType: string; ColumnType: string }>;
    Rows: any[][];
  }>;
}

export class KustoClient {
  private endpoint: string;
  private db: string;

  constructor(endpoint = 'http://127.0.0.1:8080', db = 'NetDefaultDB') {
    this.endpoint = endpoint.replace(/\/$/, '');
    this.db = db;
  }

  async isHealthy(): Promise<boolean> {
    try {
      const res = await fetch(`${this.endpoint}/v1/rest/mgmt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ db: this.db, csl: '.show version' }),
        signal: AbortSignal.timeout(2000)
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async executeMgmt(command: string): Promise<any> {
    const res = await fetch(`${this.endpoint}/v1/rest/mgmt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ db: this.db, csl: command }),
      signal: AbortSignal.timeout(10000)
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Kusto management command failed (${res.status}): ${text}`);
    }

    return res.json();
  }

  async executeQuery(query: string): Promise<Record<string, any>[]> {
    const res = await fetch(`${this.endpoint}/v1/rest/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ db: this.db, csl: query }),
      signal: AbortSignal.timeout(10000)
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Kusto query failed (${res.status}): ${text}`);
    }

    const data = (await res.json()) as KustoQueryResponse;
    if (!data.Tables || data.Tables.length === 0) return [];

    const primaryTable = data.Tables[0];
    const columns = primaryTable.Columns.map(c => c.ColumnName);
    return primaryTable.Rows.map(row => {
      const record: Record<string, any> = {};
      columns.forEach((col, idx) => {
        record[col] = row[idx];
      });
      return record;
    });
  }

  async createTable(tableName: string, columns: Array<{ name: string; type: string }>): Promise<void> {
    const colDefs = columns.map(c => `${c.name}:${c.type === 'datetime' ? 'datetime' : c.type === 'dynamic' ? 'dynamic' : 'string'}`).join(', ');
    await this.executeMgmt(`.create-merge table ${tableName} (${colDefs})`);
  }

  async ingestRows(tableName: string, columns: string[], rows: Record<string, any>[]): Promise<void> {
    if (rows.length === 0) return;

    // Convert rows to CSV format for inline ingestion
    const lines = rows.map(r => {
      return columns.map(c => {
        const val = r[c];
        if (val === undefined || val === null) return '';
        if (typeof val === 'object') return `"${JSON.stringify(val).replace(/"/g, '""')}"`;
        const str = String(val);
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      }).join(',');
    });

    const csvData = lines.join('\n');
    const cmd = `.ingest inline into table ${tableName} <|\n${csvData}`;
    await this.executeMgmt(cmd);
  }
}

