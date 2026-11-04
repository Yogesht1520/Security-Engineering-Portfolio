import React from 'react';
import { ShieldCheck, Target, Crosshair, CheckCircle2, ArrowRight, Activity, Terminal } from 'lucide-react';
import type { CatalogData, CatalogHunt } from '../types/index.js';
import { SeverityBadge, ValidationBadge, PlatformBadge } from '../components/Badges.js';

interface OverviewScreenProps {
  data: CatalogData;
  onSelectHunt: (hunt: CatalogHunt) => void;
  onNavigateToCatalog: () => void;
  onNavigateToCoverage: () => void;
}

export function OverviewScreen({ data, onSelectHunt, onNavigateToCatalog, onNavigateToCoverage }: OverviewScreenProps) {
  const tacticsList = [
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

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Welcome Banner */}
      <div className="p-5 rounded-soc bg-gradient-to-r from-blue-950/40 via-soc-surface to-soc-surface border border-soc-border flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <span>SOC Detection & Threat Hunting Telemetry Hub</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono bg-blue-900/60 text-blue-300 border border-blue-700/60">
              Microsoft Defender & Sentinel
            </span>
          </h1>
          <p className="text-xs text-soc-muted mt-1 max-w-2xl">
            Detection-as-Code library of original KQL queries mapped to MITRE ATT&CK, rigorously validated against synthetic attack telemetry and benign baseline noise in local Kusto containers.
          </p>
        </div>
        <button
          onClick={onNavigateToCatalog}
          className="px-3.5 py-2 rounded-soc bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors shadow-lg shadow-blue-600/20"
        >
          <span>Explore All 20 Hunts</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border">
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-medium">Production Hunts</span>
            <Terminal className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">{data.stats.huntCount}</div>
          <div className="mt-1 text-[11px] text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            <span>100% CI Tested</span>
          </div>
        </div>

        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border">
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-medium">Covered Techniques</span>
            <Crosshair className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">{data.stats.techniqueCount}</div>
          <div className="mt-1 text-[11px] text-soc-muted font-mono">MITRE ATT&CK v17</div>
        </div>

        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border">
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-medium">Covered Tactics</span>
            <Target className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">{data.stats.tacticCount}</div>
          <div className="mt-1 text-[11px] text-soc-muted">Enterprise Attack Matrix</div>
        </div>

        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border">
          <div className="flex items-center justify-between text-soc-muted">
            <span className="text-xs font-medium">Synthetic Validation</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
            {data.stats.validationBreakdown.synthetic} / {data.stats.huntCount}
          </div>
          <div className="mt-1 text-[11px] text-emerald-400">Deterministic Evidence</div>
        </div>
      </div>

      {/* Mini Heatmap: Tactics Coverage */}
      <div className="p-5 rounded-soc bg-soc-surface border border-soc-border space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">MITRE ATT&CK Tactics Heatmap</h2>
          </div>
          <button
            onClick={onNavigateToCoverage}
            className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium"
          >
            <span>Full Coverage Matrix</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="grid grid-cols-6 gap-2">
          {tacticsList.map((tactic) => {
            const count = data.hunts.filter((h) => h.attack.tactics.includes(tactic.id)).length;
            const hasCoverage = count > 0;
            return (
              <div
                key={tactic.id}
                className={`p-3 rounded-soc border transition-colors ${
                  hasCoverage
                    ? 'bg-blue-950/30 border-blue-800/60 hover:border-blue-500'
                    : 'bg-soc-raised/40 border-soc-border opacity-50'
                }`}
              >
                <div className="text-[11px] text-soc-muted truncate">{tactic.name}</div>
                <div className="mt-1 flex items-baseline justify-between">
                  <span className={`text-base font-bold font-mono ${hasCoverage ? 'text-blue-400' : 'text-slate-600'}`}>
                    {count}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">hunts</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Featured Flagship Hunts Table */}
      <div className="p-5 rounded-soc bg-soc-surface border border-soc-border space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-bold uppercase tracking-wider text-white">Featured Detection Hunts</h2>
          <span className="text-[11px] text-soc-muted">Showing 5 flagship queries</span>
        </div>

        <div className="divide-y divide-soc-border overflow-hidden border border-soc-border rounded-soc">
          {data.hunts.slice(0, 5).map((hunt) => (
            <div
              key={hunt.id}
              onClick={() => onSelectHunt(hunt)}
              className="p-3 bg-soc-surface hover:bg-soc-raised/60 transition-colors flex items-center justify-between cursor-pointer group"
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs font-bold text-blue-400">{hunt.id}</span>
                <div>
                  <div className="text-xs font-medium text-white group-hover:text-blue-400 transition-colors">
                    {hunt.title}
                  </div>
                  <div className="text-[11px] text-soc-muted font-mono mt-0.5">
                    {hunt.tables.join(', ')} • [{hunt.attack.techniques.join(', ')}]
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2.5">
                <PlatformBadge platform={hunt.platform} />
                <SeverityBadge severity={hunt.severity} />
                <ValidationBadge level={hunt.validation_level} tests={hunt.tests} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

