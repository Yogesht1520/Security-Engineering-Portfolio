import fs from 'node:fs';
import YAML from 'yaml';
import { faker } from '@faker-js/faker';
import {
  generateBenignUsers,
  generateBaselineSigninLogs,
  generateBaselineProcessEvents,
  generateBaselineCloudEvents,
  UserEntity
} from './baseline.js';

export interface ScenarioDefinition {
  id: string;
  title: string;
  seed: number;
  window: {
    start: string;
    duration: string;
  };
  baseline: {
    users: number;
    tables: string[];
  };
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

export function parseDurationHours(durationStr: string): number {
  const match = durationStr.match(/^(\d+)h$/);
  return match ? parseInt(match[1], 10) : 6;
}

export function parseOffsetMinutes(offsetStr: string): number {
  const match = offsetStr.match(/^\+(\d+):(\d+)$/);
  if (match) {
    return parseInt(match[1], 10) * 60 + parseInt(match[2], 10);
  }
  return 0;
}

export function generateScenarioDataset(scenario: ScenarioDefinition): Map<string, Record<string, any>[]> {
  const dataset = new Map<string, Record<string, any>[]>();
  const startTime = new Date(scenario.window.start);
  const durationHours = parseDurationHours(scenario.window.duration);

  faker.seed(scenario.seed);
  const users = generateBenignUsers(scenario.baseline.users, scenario.seed);

  // 1. Generate Baseline Data
  for (const table of scenario.baseline.tables) {
    if (table === 'SigninLogs') {
      dataset.set('SigninLogs', generateBaselineSigninLogs(users, startTime, durationHours));
    } else if (table === 'DeviceProcessEvents') {
      dataset.set('DeviceProcessEvents', generateBaselineProcessEvents(users, startTime, durationHours));
    } else if (table === 'CloudAppEvents') {
      dataset.set('CloudAppEvents', generateBaselineCloudEvents(users, startTime, durationHours));
    } else if (table === 'DeviceRegistryEvents') {
      dataset.set('DeviceRegistryEvents', []);
    }
  }

  // 2. Inject Attack Steps
  for (const step of scenario.steps) {
    const offsetMins = parseOffsetMinutes(step.at);
    const stepTime = new Date(startTime.getTime() + offsetMins * 60 * 1000).toISOString();
    const tableList = dataset.get(step.table) || [];

    if (step.table === 'SigninLogs') {
      if (step.action === 'spray') {
        const count = step.targets || 30;
        for (let i = 0; i < count; i++) {
          const targetUpn = users[i % users.length].upn;
          tableList.push({
            TimeGenerated: stepTime,
            UserPrincipalName: targetUpn,
            UserId: faker.string.uuid(),
            IPAddress: step.actor || '203.0.113.50',
            ResultType: step.details?.resultType || '50126',
            ResultDescription: step.details?.resultDescription || 'Invalid password',
            AppDisplayName: 'Office 365 Exchange Online',
            AppId: faker.string.uuid(),
            UserAgent: 'Python-requests/2.28.1',
            Location: 'RU',
            LocationDetails: { countryOrRegion: 'RU', city: 'Moscow' },
            DeviceDetail: { operatingSystem: 'Linux' },
            ConditionalAccessStatus: 'failure'
          });
        }
      } else if (step.action === 'success') {
        tableList.push({
          TimeGenerated: stepTime,
          UserPrincipalName: step.user || 'user017@contoso.test',
          UserId: faker.string.uuid(),
          IPAddress: step.actor || '203.0.113.50',
          ResultType: '0',
          ResultDescription: 'Success',
          AppDisplayName: step.details?.app || 'Office 365 Exchange Online',
          AppId: faker.string.uuid(),
          UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          Location: step.details?.location || 'DE',
          LocationDetails: { countryOrRegion: step.details?.location || 'DE', city: 'Frankfurt' },
          DeviceDetail: { operatingSystem: 'Windows 11' },
          ConditionalAccessStatus: 'success'
        });
      }
    } else if (step.table === 'DeviceProcessEvents') {
      tableList.push({
        Timestamp: stepTime,
        DeviceId: faker.string.uuid(),
        DeviceName: `${step.actor || 'WORKSTATION-01'}.corp.contoso.test`,
        ActionType: 'ProcessCreated',
        FileName: step.process || 'powershell.exe',
        FolderPath: 'C:\\Windows\\System32',
        SHA256: faker.string.hexadecimal({ length: 64, casing: 'lower', prefix: '' }),
        ProcessCommandLine: step.command || '',
        ProcessIntegrityLevel: 'High',
        ProcessTokenElevation: 'TokenElevationTypeFull',
        AccountName: (step.user || 'victim_user').split('@')[0],
        AccountDomain: 'CONTOSO',
        InitiatingProcessFileName: step.parent || 'explorer.exe',
        InitiatingProcessCommandLine: step.parent || 'explorer.exe',
        InitiatingProcessParentFileName: 'explorer.exe',
        InitiatingProcessAccountName: (step.user || 'victim_user').split('@')[0]
      });
    } else if (step.table === 'DeviceRegistryEvents') {
      tableList.push({
        Timestamp: stepTime,
        DeviceId: faker.string.uuid(),
        DeviceName: `${step.actor || 'WORKSTATION-01'}.corp.contoso.test`,
        ActionType: 'RegistryValueSet',
        RegistryKey: step.details?.registryKey || 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        RegistryValueName: step.details?.registryValueName || 'Updater',
        RegistryValueData: step.details?.registryValueData || 'C:\\Users\\Public\\update.exe',
        PreviousRegistryValueData: '',
        InitiatingProcessFileName: 'powershell.exe',
        InitiatingProcessCommandLine: 'powershell.exe -enc ...',
        InitiatingProcessAccountName: (step.user || 'victim_user').split('@')[0]
      });
    } else if (step.table === 'CloudAppEvents') {
      if (step.action === 'new_inbox_rule') {
        tableList.push({
          Timestamp: stepTime,
          ActionType: 'New-InboxRule',
          Application: 'Microsoft Exchange Online',
          AccountDisplayName: 'Victim User',
          AccountId: step.user || 'user017@contoso.test',
          AccountType: 'Regular',
          IPAddress: step.actor || '203.0.113.50',
          CountryCode: 'DE',
          City: 'Frankfurt',
          UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          ActivityType: 'New-InboxRule',
          ActivityObjects: ['InboxRule: AutoForward'],
          RawEventData: { Parameters: step.details?.ruleParameters || 'ForwardTo: attacker@evil.example' }
        });
      } else if (step.action === 'mass_download') {
        const count = step.targets || 60;
        for (let i = 0; i < count; i++) {
          tableList.push({
            Timestamp: stepTime,
            ActionType: 'FileDownloaded',
            Application: 'Microsoft SharePoint Online',
            AccountDisplayName: 'Admin User',
            AccountId: step.user || 'admin_user@contoso.test',
            AccountType: 'Admin',
            IPAddress: step.actor || '192.0.2.77',
            CountryCode: 'US',
            City: 'Dallas',
            UserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            ActivityType: 'FileDownloaded',
            ActivityObjects: [`https://contoso.sharepoint.test/sites/confidential/Doc_${i}.pdf`],
            RawEventData: { ClientIP: step.actor || '192.0.2.77', Operation: 'FileDownloaded' }
          });
        }
      }
    }

    dataset.set(step.table, tableList);
  }

  // Sort each table chronologically
  for (const [table, events] of dataset.entries()) {
    const timeKey = table.startsWith('Device') || table.startsWith('Cloud') ? 'Timestamp' : 'TimeGenerated';
    events.sort((a, b) => new Date(a[timeKey]).getTime() - new Date(b[timeKey]).getTime());
  }

  return dataset;
}

export function loadScenarioFromFile(filePath: string): ScenarioDefinition {
  const content = fs.readFileSync(filePath, 'utf8');
  return YAML.parse(content) as ScenarioDefinition;
}

