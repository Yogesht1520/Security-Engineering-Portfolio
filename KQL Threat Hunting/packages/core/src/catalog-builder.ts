import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';

export interface CatalogHunt {
  id: string;
  title: string;
  status: string;
  validation_level: string;
  platform: string;
  tables: string[];
  time_column: string;
  attack: {
    tactics: string[];
    techniques: string[];
  };
  severity: string;
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

export interface Catalog {
  schemaVersion: string;
  generated: string;
  attackVersion: string;
  stats: CatalogStats;
  hunts: CatalogHunt[];
  scenarios: any[];
}

export function buildCatalog(huntsDir: string, scenariosDir: string): Catalog {
  function findHuntYamlFiles(dir: string): string[] {
    const results: string[] = [];
    if (!fs.existsSync(dir)) return results;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...findHuntYamlFiles(full));
      } else if (entry.name.endsWith('.hunt.yml')) {
        results.push(full);
      }
    }
    return results;
  }

  const huntYamlFiles = findHuntYamlFiles(huntsDir);
  const catalogHunts: CatalogHunt[] = [];

  const uniqueTechniques = new Set<string>();
  const uniqueTactics = new Set<string>();
  const uniqueTables = new Set<string>();
  const validationBreakdown = { syntax: 0, synthetic: 0, tenant: 0 };

  for (const yamlPath of huntYamlFiles) {
    const rawYaml = fs.readFileSync(yamlPath, 'utf8');
    const meta = YAML.parse(rawYaml);
    const kqlPath = yamlPath.replace(/\.hunt\.yml$/, '.kql');
    const query = fs.existsSync(kqlPath) ? fs.readFileSync(kqlPath, 'utf8') : '';

    const testCount = Array.isArray(meta.tests) ? meta.tests.length : 0;

    meta.attack?.techniques?.forEach((t: string) => uniqueTechniques.add(t));
    meta.attack?.tactics?.forEach((t: string) => uniqueTactics.add(t));
    meta.tables?.forEach((tbl: string) => uniqueTables.add(tbl));

    const valLevel = (meta.validation_level || 'syntax') as keyof typeof validationBreakdown;
    if (validationBreakdown[valLevel] !== undefined) {
      validationBreakdown[valLevel]++;
    }

    catalogHunts.push({
      id: meta.id,
      title: meta.title,
      status: meta.status || 'tested',
      validation_level: meta.validation_level || 'syntax',
      platform: meta.platform || 'both',
      tables: meta.tables || [],
      time_column: meta.time_column || 'TimeGenerated',
      attack: meta.attack || { tactics: [], techniques: [] },
      severity: meta.severity || 'medium',
      hypothesis: meta.hypothesis || '',
      logic_summary: meta.logic_summary || '',
      parameters: meta.parameters || [],
      false_positives: meta.false_positives || [],
      tuning: meta.tuning || [],
      triage_steps: meta.triage_steps || [],
      response: meta.response || '',
      references: meta.references || [],
      query,
      tests: {
        passed: testCount,
        total: testCount
      }
    });
  }

  // Sort hunts by area and ID
  catalogHunts.sort((a, b) => a.id.localeCompare(b.id));

  // Load scenarios
  const scenarios: any[] = [];
  if (fs.existsSync(scenariosDir)) {
    const scFiles = fs.readdirSync(scenariosDir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));
    for (const scFile of scFiles) {
      const content = fs.readFileSync(path.join(scenariosDir, scFile), 'utf8');
      scenarios.push(YAML.parse(content));
    }
  }

  return {
    schemaVersion: '1.0.0',
    generated: new Date().toISOString(),
    attackVersion: 'v17',
    stats: {
      huntCount: catalogHunts.length,
      techniqueCount: uniqueTechniques.size,
      tacticCount: uniqueTactics.size,
      tableCount: uniqueTables.size,
      validationBreakdown
    },
    hunts: catalogHunts,
    scenarios
  };
}

