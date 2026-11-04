export interface CatalogHunt {
  id: string;
  title: string;
  status: string;
  validation_level: 'syntax' | 'synthetic' | 'tenant';
  platform: 'sentinel' | 'defender-xdr' | 'both';
  tables: string[];
  time_column: string;
  attack: {
    tactics: string[];
    techniques: string[];
  };
  severity: 'informational' | 'low' | 'medium' | 'high';
  hypothesis: string;
  logic_summary: string;
  parameters: Array<{ name: string; default: any; description: string }>;
  false_positives: string[];
  tuning: string[];
  triage_steps: string[];
  response: string;
  references?: Array<{ title: string; url: string }>;
  query: string;
  tests: {
    passed: number;
    total: number;
  };
}

export interface CatalogStats {
  huntCount: number;
  techniqueCount: number;
  tacticCount: number;
  tableCount: number;
  validationBreakdown: {
    syntax: number;
    synthetic: number;
    tenant: number;
  };
}

export interface ScenarioDefinition {
  id: string;
  title: string;
  seed: number;
  window: { start: string; duration: string };
  baseline: { users: number; tables: string[] };
  steps: Array<{
    at: string;
    actor?: string;
    action: string;
    table: string;
    attack?: string;
    user?: string;
    targets?: number;
    process?: string;
    parent?: string;
    command?: string;
    details?: Record<string, any>;
  }>;
}

export interface CatalogData {
  schemaVersion: string;
  generated: string;
  attackVersion: string;
  stats: CatalogStats;
  hunts: CatalogHunt[];
  scenarios: ScenarioDefinition[];
}

export type ScreenId = 'overview' | 'catalog' | 'detail' | 'coverage' | 'scenarios' | 'validation' | 'about';

