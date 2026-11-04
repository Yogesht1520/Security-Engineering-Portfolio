import YAML from 'yaml';
import type { CatalogHunt } from './catalog-builder.js';

export function capitalizeTactic(tactic: string): string {
  return tactic
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join('');
}

export function exportSentinelAnalyticsRule(hunt: CatalogHunt): string {
  // Map tables to connectors
  const connectorMap: Record<string, { id: string; dataTypes: string[] }> = {
    SigninLogs: { id: 'AzureActiveDirectory', dataTypes: ['SigninLogs'] },
    AuditLogs: { id: 'AzureActiveDirectory', dataTypes: ['AuditLogs'] },
    AzureActivity: { id: 'AzureActivity', dataTypes: ['AzureActivity'] },
    DeviceProcessEvents: { id: 'MicrosoftDefenderAdvancedThreatProtection', dataTypes: ['DeviceProcessEvents'] },
    DeviceRegistryEvents: { id: 'MicrosoftDefenderAdvancedThreatProtection', dataTypes: ['DeviceRegistryEvents'] },
    DeviceEvents: { id: 'MicrosoftDefenderAdvancedThreatProtection', dataTypes: ['DeviceEvents'] },
    DeviceNetworkEvents: { id: 'MicrosoftDefenderAdvancedThreatProtection', dataTypes: ['DeviceNetworkEvents'] },
    DeviceFileEvents: { id: 'MicrosoftDefenderAdvancedThreatProtection', dataTypes: ['DeviceFileEvents'] },
    DeviceLogonEvents: { id: 'MicrosoftDefenderAdvancedThreatProtection', dataTypes: ['DeviceLogonEvents'] },
    CloudAppEvents: { id: 'MicrosoftCloudAppSecurity', dataTypes: ['CloudAppEvents'] },
    EmailAttachmentInfo: { id: 'MicrosoftDefenderForOffice365', dataTypes: ['EmailAttachmentInfo'] },
    UrlClickEvents: { id: 'MicrosoftDefenderForOffice365', dataTypes: ['UrlClickEvents'] }
  };

  const connectors = hunt.tables.map(tbl => {
    return connectorMap[tbl] || { id: 'Custom', dataTypes: [tbl] };
  });

  // Infer entity mappings from primary table
  const entityMappings: any[] = [];
  if (hunt.tables.includes('SigninLogs')) {
    entityMappings.push({
      entityType: 'Account',
      fieldMappings: [{ identifier: 'FullName', columnName: 'UserPrincipalName' }]
    });
    entityMappings.push({
      entityType: 'IP',
      fieldMappings: [{ identifier: 'Address', columnName: 'IPAddress' }]
    });
  } else if (hunt.tables.includes('AzureActivity')) {
    entityMappings.push({
      entityType: 'Account',
      fieldMappings: [{ identifier: 'FullName', columnName: 'Caller' }]
    });
    entityMappings.push({
      entityType: 'IP',
      fieldMappings: [{ identifier: 'Address', columnName: 'CallerIpAddress' }]
    });
  } else if (
    hunt.tables.includes('DeviceProcessEvents') || 
    hunt.tables.includes('DeviceRegistryEvents') ||
    hunt.tables.includes('DeviceEvents') ||
    hunt.tables.includes('DeviceFileEvents') ||
    hunt.tables.includes('DeviceLogonEvents')
  ) {
    entityMappings.push({
      entityType: 'Host',
      fieldMappings: [{ identifier: 'HostName', columnName: 'DeviceName' }]
    });
    entityMappings.push({
      entityType: 'Account',
      fieldMappings: [{ identifier: 'Name', columnName: 'AccountName' }]
    });
  } else if (hunt.tables.includes('DeviceNetworkEvents')) {
    entityMappings.push({
      entityType: 'Host',
      fieldMappings: [{ identifier: 'HostName', columnName: 'DeviceName' }]
    });
    entityMappings.push({
      entityType: 'IP',
      fieldMappings: [{ identifier: 'Address', columnName: 'RemoteIP' }]
    });
  } else if (hunt.tables.includes('CloudAppEvents')) {
    entityMappings.push({
      entityType: 'Account',
      fieldMappings: [{ identifier: 'Name', columnName: 'AccountId' }]
    });
    entityMappings.push({
      entityType: 'IP',
      fieldMappings: [{ identifier: 'Address', columnName: 'IPAddress' }]
    });
  } else if (hunt.tables.includes('UrlClickEvents')) {
    entityMappings.push({
      entityType: 'Account',
      fieldMappings: [{ identifier: 'FullName', columnName: 'AccountUpn' }]
    });
    entityMappings.push({
      entityType: 'Url',
      fieldMappings: [{ identifier: 'Url', columnName: 'Url' }]
    });
  }

  // Capitalize severity (medium -> Medium)
  const severity = hunt.severity.charAt(0).toUpperCase() + hunt.severity.slice(1);

  // Map tactics
  const tactics = hunt.attack.tactics.map(capitalizeTactic);

  const ruleObject = {
    id: hunt.id,
    name: hunt.title,
    description: hunt.hypothesis.trim(),
    severity,
    status: 'Available',
    requiredDataConnectors: connectors,
    queryFrequency: 'PT1H',
    queryPeriod: 'PT1D',
    triggerOperator: 'GreaterThan',
    triggerThreshold: 0,
    tactics,
    relevantTechniques: hunt.attack.techniques,
    query: hunt.query.trim(),
    entityMappings,
    customDetails: {
      HuntBookId: hunt.id,
      ValidationLevel: hunt.validation_level
    },
    version: '1.0.0',
    kind: 'Scheduled'
  };

  return YAML.stringify(ruleObject);
}

