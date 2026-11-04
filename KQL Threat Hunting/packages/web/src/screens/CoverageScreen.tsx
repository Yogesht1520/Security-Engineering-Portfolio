import React, { useState } from 'react';
import { Download, Layers, ShieldCheck, Crosshair, ArrowRight } from 'lucide-react';
import type { CatalogData, CatalogHunt } from '../types/index.js';

interface CoverageScreenProps {
  data: CatalogData;
  onFilterTechnique: (tech: string) => void;
}

export function CoverageScreen({ data, onFilterTechnique }: CoverageScreenProps) {
  const tactics = [
    { id: 'initial-access', name: 'Initial Access' },
    { id: 'execution', name: 'Execution' },
    { id: 'persistence', name: 'Persistence' },
    { id: 'privilege-escalation', name: 'Privilege Esc' },
    { id: 'defense-evasion', name: 'Defense Evasion' },
    { id: 'credential-access', name: 'Credential Access' },
    { id: 'lateral-movement', name: 'Lateral Movement' },
    { id: 'collection', name: 'Collection' },
    { id: 'command-and-control', name: 'Command & Control' },
    { id: 'exfiltration', name: 'Exfiltration' },
    { id: 'impact', name: 'Impact' }
  ];

  function handleDownloadNavigatorLayer() {
    // Construct Navigator Layer JSON
    const techMap = new Map<string, { hunts: string[]; count: number }>();
    data.hunts.forEach((h) => {
      h.attack.techniques.forEach((t) => {
        if (!techMap.has(t)) techMap.set(t, { hunts: [h.id], count: 1 });
        else {
          const item = techMap.get(t)!;
          if (!item.hunts.includes(h.id)) item.hunts.push(h.id);
          item.count++;
        }
      });
    });

    const navigatorTechniques = Array.from(techMap.entries()).map(([techId, meta]) => ({
      techniqueID: techId,
      score: meta.count,
      color: '#3B82F6',
      comment: `HuntBook: ${meta.hunts.join(', ')}`,
      enabled: true
    }));

    const layer = {
      name: 'HuntBook ATT&CK Coverage Matrix',
      versions: { attack: '17', navigator: '4.5.1', layer: '4.5' },
      domain: 'enterprise-attack',
      description: `HuntBook KQL detection-as-code coverage (${data.stats.huntCount} hunts across ${techMap.size} techniques)`,
      techniques: navigatorTechniques,
      gradient: { colors: ['#0f172a', '#3B82F6', '#22C55E'], minValue: 0, maxValue: 3 }
    };

    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'huntbook-navigator-layer.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="p-5 rounded-soc bg-soc-surface border border-soc-border flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <span>MITRE ATT&CK Matrix Coverage</span>
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Visualizing detection coverage across Enterprise ATT&CK v17 tactics and techniques.
          </p>
        </div>

        <button
          onClick={handleDownloadNavigatorLayer}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-soc bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-colors shadow-lg shadow-blue-600/20"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Download Navigator Layer JSON</span>
        </button>
      </div>

      {/* Coverage Grid */}
      <div className="grid grid-cols-11 gap-2.5 overflow-x-auto pb-4">
        {tactics.map((tactic) => {
          const matchingHunts = data.hunts.filter((h) => h.attack.tactics.includes(tactic.id));
          const techSet = new Set(matchingHunts.flatMap((h) => h.attack.techniques));
          const techList = Array.from(techSet);

          return (
            <div key={tactic.id} className="min-w-[120px] flex flex-col space-y-2">
              {/* Tactic Column Header */}
              <div className="p-2.5 rounded-soc bg-soc-raised border border-soc-border text-center">
                <div className="text-[11px] font-bold text-white leading-tight">{tactic.name}</div>
                <div className="text-[10px] text-blue-400 font-mono mt-1">
                  {techList.length} {techList.length === 1 ? 'tech' : 'techs'}
                </div>
              </div>

              {/* Technique Cards */}
              <div className="space-y-1.5">
                {techList.length === 0 ? (
                  <div className="p-3 rounded-soc bg-soc-surface/40 border border-soc-border/40 text-[10px] text-slate-600 text-center">
                    No Hunts
                  </div>
                ) : (
                  techList.map((tech) => {
                    const huntsForTech = matchingHunts.filter((h) => h.attack.techniques.includes(tech));
                    return (
                      <div
                        key={tech}
                        onClick={() => onFilterTechnique(tech)}
                        className="p-2 rounded-soc bg-blue-950/40 border border-blue-800/60 hover:border-blue-400 transition-colors cursor-pointer group"
                      >
                        <div className="text-[11px] font-mono font-bold text-blue-400 group-hover:text-blue-300">
                          {tech}
                        </div>
                        <div className="text-[10px] text-soc-muted truncate mt-0.5">
                          {huntsForTech.map((h) => h.id).join(', ')}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

