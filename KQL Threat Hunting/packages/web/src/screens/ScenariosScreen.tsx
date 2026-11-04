import React, { useState } from 'react';
import { PlaySquare, Clock, ArrowRight, ShieldAlert, CheckCircle2 } from 'lucide-react';
import type { ScenarioDefinition, CatalogHunt } from '../types/index.js';

interface ScenariosScreenProps {
  scenarios: ScenarioDefinition[];
  hunts: CatalogHunt[];
  onSelectHunt: (hunt: CatalogHunt) => void;
}

export function ScenariosScreen({ scenarios, hunts, onSelectHunt }: ScenariosScreenProps) {
  const [selectedScenarioId, setSelectedScenarioId] = useState(scenarios[0]?.id || 'scenario-01');

  const currentScenario = scenarios.find((s) => s.id === selectedScenarioId) || scenarios[0];

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="p-5 rounded-soc bg-soc-surface border border-soc-border flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-white flex items-center gap-2">
            <PlaySquare className="w-4 h-4 text-blue-400" />
            <span>Attack Scenario Replay & Kill-Chain Timeline</span>
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Simulate realistic multi-stage cyber attacks and visualize which KQL threat hunts fire at each phase.
          </p>
        </div>

        {/* Scenario Switcher */}
        <div className="flex items-center gap-2">
          {scenarios.map((sc) => (
            <button
              key={sc.id}
              onClick={() => setSelectedScenarioId(sc.id)}
              className={`px-3 py-1.5 rounded-soc text-xs font-mono transition-colors ${
                selectedScenarioId === sc.id
                  ? 'bg-blue-600 text-white font-medium shadow-md shadow-blue-600/20'
                  : 'bg-soc-raised border border-soc-border text-soc-muted hover:text-white'
              }`}
            >
              {sc.id}
            </button>
          ))}
        </div>
      </div>

      {/* Scenario Metadata Card */}
      {currentScenario && (
        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white">{currentScenario.title}</h2>
            <div className="flex items-center gap-2 text-xs font-mono text-soc-muted">
              <span>Seed: {currentScenario.seed}</span>
              <span>•</span>
              <span>Duration: {currentScenario.window.duration}</span>
              <span>•</span>
              <span>Baseline: {currentScenario.baseline.users} users</span>
            </div>
          </div>
          <div className="text-xs text-soc-muted">
            Target Tables: {currentScenario.baseline.tables.join(', ')}
          </div>
        </div>
      )}

      {/* Kill Chain Timeline */}
      {currentScenario && (
        <div className="space-y-3 relative before:absolute before:inset-0 before:left-5 before:w-0.5 before:bg-soc-border">
          {currentScenario.steps.map((step, idx) => {
            const matchingHunt = hunts.find((h) =>
              step.attack ? h.attack.techniques.includes(step.attack) : false
            );

            return (
              <div key={idx} className="relative flex items-start gap-4 pl-12 group">
                {/* Node icon on timeline */}
                <div className="absolute left-3.5 top-3 w-3 h-3 rounded-full bg-blue-500 border-2 border-soc-app ring-4 ring-blue-950/80"></div>

                {/* Event Card */}
                <div className="flex-1 p-4 rounded-soc bg-soc-surface border border-soc-border space-y-2 hover:border-blue-500/50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-blue-400 bg-soc-raised px-2 py-0.5 rounded border border-soc-border">
                        {step.at}
                      </span>
                      <span className="text-xs font-bold text-white uppercase tracking-wider">
                        {step.action.replace(/_/g, ' ')}
                      </span>
                      {step.attack && (
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-800/60">
                          {step.attack}
                        </span>
                      )}
                    </div>
                    <span className="text-xs font-mono text-soc-muted">
                      Table: {step.table}
                    </span>
                  </div>

                  {/* Step Description / Command */}
                  <div className="text-xs text-slate-300 font-mono bg-soc-app/60 p-2 rounded border border-soc-border/60 overflow-x-auto">
                    {step.command ? (
                      <code>{step.command}</code>
                    ) : (
                      <span>
                        Actor: {step.actor || 'N/A'} {step.user ? `-> Target: ${step.user}` : ''} {step.targets ? `(${step.targets} accounts)` : ''}
                      </span>
                    )}
                  </div>

                  {/* Triggered Hunt Banner */}
                  {matchingHunt ? (
                    <div className="pt-1 flex items-center justify-between border-t border-soc-border/60">
                      <div className="flex items-center gap-1.5 text-xs text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Fires Hunt: <strong className="font-mono text-white">{matchingHunt.id}</strong> — {matchingHunt.title}</span>
                      </div>
                      <button
                        onClick={() => onSelectHunt(matchingHunt)}
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium"
                      >
                        <span>View Query</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  ) : (
                    <div className="pt-1 text-[11px] text-soc-muted">
                      Step ingested as attack telemetry.
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

