import React, { useState } from 'react';
import { Search, Filter, Terminal, X } from 'lucide-react';
import type { CatalogHunt } from '../types/index.js';
import { SeverityBadge, ValidationBadge, PlatformBadge } from '../components/Badges.js';

interface CatalogScreenProps {
  hunts: CatalogHunt[];
  onSelectHunt: (hunt: CatalogHunt) => void;
  initialPlatform?: string;
}

export function CatalogScreen({ hunts, onSelectHunt, initialPlatform = 'all' }: CatalogScreenProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [selectedPlatform, setSelectedPlatform] = useState(initialPlatform);
  const [selectedTactic, setSelectedTactic] = useState('all');

  const tactics = Array.from(new Set(hunts.flatMap((h) => h.attack.tactics))).sort();

  const filteredHunts = hunts.filter((h) => {
    // Search filter
    const q = searchTerm.toLowerCase();
    const matchesSearch =
      !searchTerm ||
      h.id.toLowerCase().includes(q) ||
      h.title.toLowerCase().includes(q) ||
      h.tables.some((t) => t.toLowerCase().includes(q)) ||
      h.attack.techniques.some((tech) => tech.toLowerCase().includes(q));

    // Platform filter
    const matchesPlatform =
      selectedPlatform === 'all' ||
      h.platform === selectedPlatform ||
      h.platform === 'both';

    // Severity filter
    const matchesSeverity =
      selectedSeverity === 'all' ||
      h.severity.toLowerCase() === selectedSeverity.toLowerCase();

    // Tactic filter
    const matchesTactic =
      selectedTactic === 'all' ||
      h.attack.tactics.includes(selectedTactic);

    return matchesSearch && matchesPlatform && matchesSeverity && matchesTactic;
  });

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      {/* Title & Filter Bar */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-white flex items-center gap-2">
            <span>Threat Hunting Query Catalog</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-soc-raised border border-soc-border text-soc-muted">
              {filteredHunts.length} of {hunts.length} Hunts
            </span>
          </h1>
          <p className="text-xs text-soc-muted mt-0.5">
            Filter by MITRE ATT&CK technique, security telemetry source, or severity
          </p>
        </div>
      </div>

      {/* Filter Controls Row */}
      <div className="p-3 rounded-soc bg-soc-surface border border-soc-border flex items-center gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-soc-muted" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search queries, tables, techniques (e.g. T1110.003)..."
            className="w-full pl-9 pr-8 py-1.5 rounded-soc bg-soc-raised border border-soc-border text-xs text-white placeholder-soc-muted focus:outline-none focus:border-blue-500"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-2.5 top-2 text-soc-muted hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Tactic dropdown */}
        <select
          value={selectedTactic}
          onChange={(e) => setSelectedTactic(e.target.value)}
          className="px-2.5 py-1.5 rounded-soc bg-soc-raised border border-soc-border text-xs text-soc-text focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Tactics</option>
          {tactics.map((tac) => (
            <option key={tac} value={tac}>
              {tac}
            </option>
          ))}
        </select>

        {/* Severity dropdown */}
        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value)}
          className="px-2.5 py-1.5 rounded-soc bg-soc-raised border border-soc-border text-xs text-soc-text focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Platform dropdown */}
        <select
          value={selectedPlatform}
          onChange={(e) => setSelectedPlatform(e.target.value)}
          className="px-2.5 py-1.5 rounded-soc bg-soc-raised border border-soc-border text-xs text-soc-text focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Platforms</option>
          <option value="sentinel">Sentinel</option>
          <option value="defender-xdr">Defender XDR</option>
        </select>
      </div>

      {/* Catalog Table */}
      <div className="border border-soc-border rounded-soc overflow-hidden bg-soc-surface">
        <table className="w-full text-left text-xs">
          <thead className="bg-soc-raised/80 border-b border-soc-border text-[11px] uppercase font-mono text-soc-muted">
            <tr>
              <th className="py-2.5 px-4 font-semibold">Hunt ID</th>
              <th className="py-2.5 px-4 font-semibold">Title & Hypothesis</th>
              <th className="py-2.5 px-4 font-semibold">ATT&CK Technique</th>
              <th className="py-2.5 px-4 font-semibold">Platform & Table</th>
              <th className="py-2.5 px-4 font-semibold">Severity</th>
              <th className="py-2.5 px-4 font-semibold">Validation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-border/60">
            {filteredHunts.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-xs text-soc-muted">
                  No hunts match the selected filters.
                </td>
              </tr>
            ) : (
              filteredHunts.map((hunt) => (
                <tr
                  key={hunt.id}
                  onClick={() => onSelectHunt(hunt)}
                  className="hover:bg-soc-raised/60 transition-colors cursor-pointer group"
                >
                  <td className="py-3 px-4 font-mono font-bold text-blue-400 whitespace-nowrap">
                    {hunt.id}
                  </td>
                  <td className="py-3 px-4">
                    <div className="font-semibold text-white group-hover:text-blue-400 transition-colors">
                      {hunt.title}
                    </div>
                    <div className="text-[11px] text-soc-muted line-clamp-1 mt-0.5">
                      {hunt.hypothesis}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                    {hunt.attack.techniques.map((t) => (
                      <span
                        key={t}
                        className="px-1.5 py-0.5 rounded bg-soc-raised border border-soc-border text-[11px]"
                      >
                        {t}
                      </span>
                    ))}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <PlatformBadge platform={hunt.platform} />
                      <span className="font-mono text-[11px] text-soc-muted">
                        {hunt.tables.join(', ')}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <SeverityBadge severity={hunt.severity} />
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <ValidationBadge level={hunt.validation_level} tests={hunt.tests} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

