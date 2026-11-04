import type { Catalog } from './catalog-builder.js';

export interface TechniqueCoverage {
  techniqueId: string;
  name?: string;
  tactics: string[];
  huntIds: string[];
  count: number;
  highestValidationLevel: 'syntax' | 'synthetic' | 'tenant';
}

export interface CoverageReport {
  generated: string;
  attackVersion: string;
  coveredTactics: string[];
  coveredTechniques: TechniqueCoverage[];
  coverageStats: {
    totalHunts: number;
    totalTechniques: number;
    totalTactics: number;
  };
}

export interface NavigatorLayer {
  name: string;
  versions: {
    attack: string;
    navigator: string;
    layer: string;
  };
  domain: string;
  description: string;
  techniques: Array<{
    techniqueID: string;
    score: number;
    color: string;
    comment: string;
    enabled: boolean;
  }>;
  gradient: {
    colors: string[];
    minValue: number;
    maxValue: number;
  };
}

export function buildCoverage(catalog: Catalog): { coverage: CoverageReport; navigatorLayer: NavigatorLayer } {
  const techniqueMap = new Map<string, TechniqueCoverage>();
  const tacticSet = new Set<string>();

  for (const hunt of catalog.hunts) {
    for (const tech of hunt.attack.techniques) {
      if (!techniqueMap.has(tech)) {
        techniqueMap.set(tech, {
          techniqueId: tech,
          tactics: hunt.attack.tactics,
          huntIds: [hunt.id],
          count: 1,
          highestValidationLevel: hunt.validation_level as any
        });
      } else {
        const item = techniqueMap.get(tech)!;
        if (!item.huntIds.includes(hunt.id)) {
          item.huntIds.push(hunt.id);
          item.count++;
        }
        if (hunt.validation_level === 'tenant') item.highestValidationLevel = 'tenant';
        else if (hunt.validation_level === 'synthetic' && item.highestValidationLevel !== 'tenant') {
          item.highestValidationLevel = 'synthetic';
        }
      }
    }
    hunt.attack.tactics.forEach(t => tacticSet.add(t));
  }

  const coveredTechniques = Array.from(techniqueMap.values()).sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));

  const coverage: CoverageReport = {
    generated: new Date().toISOString(),
    attackVersion: catalog.attackVersion,
    coveredTactics: Array.from(tacticSet),
    coveredTechniques,
    coverageStats: {
      totalHunts: catalog.stats.huntCount,
      totalTechniques: coveredTechniques.length,
      totalTactics: tacticSet.size
    }
  };

  const navigatorTechniques = coveredTechniques.map(t => {
    let color = '#3B82F6'; // Synthetic default blue
    if (t.highestValidationLevel === 'tenant') color = '#22C55E';
    else if (t.highestValidationLevel === 'syntax') color = '#64748B';

    return {
      techniqueID: t.techniqueId,
      score: t.count,
      color,
      comment: `HuntBook: ${t.huntIds.join(', ')} (${t.highestValidationLevel})`,
      enabled: true
    };
  });

  const navigatorLayer: NavigatorLayer = {
    name: 'HuntBook ATT&CK Coverage Matrix',
    versions: {
      attack: '17',
      navigator: '4.5.1',
      layer: '4.5'
    },
    domain: 'enterprise-attack',
    description: `Coverage layer for HuntBook detection-as-code repository (${catalog.stats.huntCount} hunts across ${coveredTechniques.length} techniques)`,
    techniques: navigatorTechniques,
    gradient: {
      colors: ['#0f172a', '#3B82F6', '#22C55E'],
      minValue: 0,
      maxValue: 3
    }
  };

  return { coverage, navigatorLayer };
}

