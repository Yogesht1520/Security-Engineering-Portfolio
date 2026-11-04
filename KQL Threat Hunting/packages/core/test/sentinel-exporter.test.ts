import { describe, it, expect } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import { buildCatalog, exportSentinelAnalyticsRule } from '../src/index.js';

describe('Sentinel Analytics Rule Exporter', () => {
  it('correctly exports HB-ID-001 to a valid Scheduled Analytics Rule YAML', () => {
    const rootDir = path.resolve(__dirname, '../../..');
    const catalog = buildCatalog(path.join(rootDir, 'hunts'), path.join(rootDir, 'scenarios'));
    const hunt = catalog.hunts.find(h => h.id === 'HB-ID-001');

    expect(hunt).toBeDefined();
    const yamlStr = exportSentinelAnalyticsRule(hunt!);

    expect(yamlStr).toContain('id: HB-ID-001');
    expect(yamlStr).toContain('name: Password spray against multiple accounts');
    expect(yamlStr).toContain('AzureActiveDirectory');
    expect(yamlStr).toContain('SigninLogs');
    expect(yamlStr).toContain('tactics:\n  - CredentialAccess');
    expect(yamlStr).toContain('T1110.003');
    expect(yamlStr).toContain('entityType: Account');
    expect(yamlStr).toContain('columnName: UserPrincipalName');
  });
});
