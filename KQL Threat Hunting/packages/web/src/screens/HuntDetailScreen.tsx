import React, { useState } from 'react';
import {
  ArrowLeft,
  Copy,
  Check,
  Download,
  AlertTriangle,
  Sliders,
  CheckCircle2,
  Play,
  Terminal,
  ShieldCheck,
  ExternalLink,
  Clock,
  Database
} from 'lucide-react';
import type { CatalogHunt } from '../types/index.js';
import { SeverityBadge, ValidationBadge, PlatformBadge } from '../components/Badges.js';

interface HuntDetailScreenProps {
  hunt: CatalogHunt;
  onBack: () => void;
}

export function HuntDetailScreen({ hunt, onBack }: HuntDetailScreenProps) {
  const [copiedQuery, setCopiedQuery] = useState(false);
  const [copiedYaml, setCopiedYaml] = useState(false);
  const [activeTab, setActiveTab] = useState<'kql' | 'sentinel' | 'lab'>('kql');

  // Lab execution state
  const [isRunning, setIsRunning] = useState(false);
  const [labResult, setLabResult] = useState<{ rows: any[]; count: number; timeMs: number } | null>(null);
  const [labError, setLabError] = useState<string | null>(null);

  function handleCopyKql() {
    navigator.clipboard.writeText(hunt.query);
    setCopiedQuery(true);
    setTimeout(() => setCopiedQuery(false), 2000);
  }

  // Generate Sentinel YAML template on the fly
  const sentinelYaml = `id: ${hunt.id}
name: "${hunt.title}"
description: "${hunt.hypothesis.trim().replace(/"/g, '\\"')}"
severity: ${hunt.severity.charAt(0).toUpperCase() + hunt.severity.slice(1)}
status: Available
requiredDataConnectors:
  - id: ${hunt.platform === 'sentinel' ? 'AzureActiveDirectory' : 'MicrosoftDefenderAdvancedThreatProtection'}
    dataTypes:
      - ${hunt.tables[0]}
queryFrequency: PT1H
queryPeriod: PT1D
triggerOperator: GreaterThan
triggerThreshold: 0
tactics:
${hunt.attack.tactics.map(t => `  - ${t.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('')}`).join('\n')}
relevantTechniques:
${hunt.attack.techniques.map(t => `  - ${t}`).join('\n')}
query: |
${hunt.query.split('\n').map(l => `  ${l}`).join('\n')}
version: 1.0.0
kind: Scheduled`;

  function handleCopyYaml() {
    navigator.clipboard.writeText(sentinelYaml);
    setCopiedYaml(true);
    setTimeout(() => setCopiedYaml(false), 2000);
  }

  function handleDownloadYaml() {
    const blob = new Blob([sentinelYaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${hunt.id}-sentinel-rule.yml`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleRunInLab() {
    setActiveTab('lab');
    setIsRunning(true);
    setLabError(null);
    setLabResult(null);

    try {
      const res = await fetch('http://127.0.0.1:3001/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: hunt.query })
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}: Failed to execute query in Lab.`);
      }

      const data = await res.json();
      setLabResult({
        rows: data.rows || [],
        count: data.count || 0,
        timeMs: data.executionTimeMs || 0
      });
    } catch (err) {
      setLabError(
        err instanceof Error
          ? err.message
          : 'Could not connect to Lab API at http://127.0.0.1:3001. Start the container with "docker compose up -d".'
      );
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Back Button & Breadcrumb */}
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-soc bg-soc-raised border border-soc-border text-xs text-soc-muted hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Catalog</span>
        </button>
        <div className="text-xs text-soc-muted font-mono">
          hunts / {hunt.id}
        </div>
      </div>

      {/* Hero Header */}
      <div className="p-5 rounded-soc bg-soc-surface border border-soc-border space-y-3">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-blue-400 bg-blue-950/60 px-2 py-0.5 rounded border border-blue-800/60">
                {hunt.id}
              </span>
              <h1 className="text-lg font-bold text-white">{hunt.title}</h1>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <PlatformBadge platform={hunt.platform} />
              <SeverityBadge severity={hunt.severity} />
              <ValidationBadge level={hunt.validation_level} tests={hunt.tests} />
              <span className="font-mono text-xs text-slate-400 px-2 py-0.5 rounded bg-soc-raised border border-soc-border">
                Tables: {hunt.tables.join(', ')}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleRunInLab}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-soc bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-colors shadow-md shadow-blue-600/20"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run in Lab</span>
            </button>
            {hunt.attack.techniques.map((tech) => (
              <a
                key={tech}
                href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}/`}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-soc-raised border border-soc-border text-xs font-mono text-blue-400 hover:text-blue-300 hover:border-blue-500 transition-colors"
              >
                <span>{tech}</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            ))}
          </div>
        </div>
      </div>

      {/* Main Grid: Left Column Details & Right Column Code */}
      <div className="grid grid-cols-12 gap-5">
        {/* Left Column (5 cols) */}
        <div className="col-span-5 space-y-4">
          {/* Threat Hypothesis & Logic */}
          <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-3">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Threat Hypothesis
              </h3>
              <p className="text-xs text-soc-muted mt-1 leading-relaxed">
                {hunt.hypothesis}
              </p>
            </div>
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Detection Logic Summary
              </h3>
              <p className="text-xs text-soc-muted mt-1 leading-relaxed">
                {hunt.logic_summary}
              </p>
            </div>
          </div>

          {/* Triage Steps */}
          <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
              <span>SOC Triage Steps</span>
            </h3>
            <ol className="list-decimal list-inside space-y-1.5 text-xs text-soc-muted leading-relaxed">
              {hunt.triage_steps.map((step, idx) => (
                <li key={idx} className="pl-1">
                  <span className="text-slate-200">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* False Positives & Tuning */}
          <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-3">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Known False Positives</span>
              </h3>
              <ul className="list-disc list-inside space-y-1 text-xs text-soc-muted mt-1.5">
                {hunt.false_positives.map((fp, idx) => (
                  <li key={idx}>{fp}</li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <Sliders className="w-3.5 h-3.5" />
                <span>Tuning Guidance</span>
              </h3>
              <ul className="list-disc list-inside space-y-1 text-xs text-soc-muted mt-1.5">
                {hunt.tuning.map((t, idx) => (
                  <li key={idx}>{t}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Parameters Table */}
          {hunt.parameters && hunt.parameters.length > 0 && (
            <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Configurable Parameters
              </h3>
              <div className="divide-y divide-soc-border border border-soc-border rounded text-xs font-mono">
                {hunt.parameters.map((p) => (
                  <div key={p.name} className="p-2 flex items-center justify-between">
                    <div>
                      <span className="text-blue-400 font-bold">{p.name}</span>
                      <span className="text-slate-500 text-[11px] ml-2 font-sans">{p.description}</span>
                    </div>
                    <span className="px-1.5 py-0.5 rounded bg-soc-raised text-slate-300 text-[11px]">
                      {String(p.default)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: KQL Query & Sentinel YAML Exporter & Lab Execution (7 cols) */}
        <div className="col-span-7 space-y-4">
          <div className="rounded-soc bg-soc-surface border border-soc-border overflow-hidden flex flex-col min-h-[500px]">
            {/* Tab Header */}
            <div className="px-4 py-2.5 bg-soc-raised/80 border-b border-soc-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('kql')}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                    activeTab === 'kql'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-soc-muted hover:text-white'
                  }`}
                >
                  KQL Threat Hunt Query
                </button>
                <button
                  onClick={() => setActiveTab('sentinel')}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                    activeTab === 'sentinel'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-soc-muted hover:text-white'
                  }`}
                >
                  Sentinel Analytics Rule YAML
                </button>
                <button
                  onClick={() => setActiveTab('lab')}
                  className={`px-3 py-1 rounded text-xs font-medium flex items-center gap-1 transition-colors ${
                    activeTab === 'lab'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-soc-muted hover:text-white'
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Lab Execution</span>
                </button>
              </div>

              {activeTab === 'kql' ? (
                <button
                  onClick={handleCopyKql}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-soc-surface hover:bg-slate-700 border border-soc-border text-xs text-white transition-colors"
                >
                  {copiedQuery ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedQuery ? 'Copied' : 'Copy KQL'}</span>
                </button>
              ) : activeTab === 'sentinel' ? (
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyYaml}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-soc-surface hover:bg-slate-700 border border-soc-border text-xs text-white transition-colors"
                  >
                    {copiedYaml ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedYaml ? 'Copied' : 'Copy YAML'}</span>
                  </button>
                  <button
                    onClick={handleDownloadYaml}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-xs text-white transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download</span>
                  </button>
                </div>
              ) : (
                <button
                  onClick={handleRunInLab}
                  disabled={isRunning}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-xs text-white transition-colors"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{isRunning ? 'Executing...' : 'Re-run Query'}</span>
                </button>
              )}
            </div>

            {/* Code / Lab Body */}
            {activeTab === 'kql' ? (
              <div className="p-4 bg-soc-app overflow-x-auto flex-1 font-mono text-xs leading-relaxed text-slate-200">
                <pre>
                  <code>{hunt.query}</code>
                </pre>
              </div>
            ) : activeTab === 'sentinel' ? (
              <div className="p-4 bg-soc-app overflow-x-auto flex-1 font-mono text-xs leading-relaxed text-slate-200">
                <pre>
                  <code>{sentinelYaml}</code>
                </pre>
              </div>
            ) : (
              <div className="p-4 bg-soc-app flex-1 flex flex-col justify-start space-y-3 font-mono text-xs">
                {isRunning ? (
                  <div className="py-16 text-center text-soc-muted space-y-2">
                    <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
                    <div>Executing KQL query against Kusto emulator...</div>
                  </div>
                ) : labError ? (
                  <div className="p-4 rounded bg-amber-950/30 border border-amber-800/60 text-amber-300 space-y-2">
                    <div className="font-bold flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                      <span>Lab Execution Offline</span>
                    </div>
                    <p className="text-xs text-amber-200/80 font-sans leading-relaxed">
                      {labError}
                    </p>
                    <div className="pt-2 text-[11px] text-slate-400 border-t border-amber-900/40">
                      <strong>To run KQL live on your machine:</strong>
                      <pre className="mt-1 p-2 bg-black/40 rounded text-blue-300">docker compose up -d</pre>
                    </div>
                  </div>
                ) : labResult ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-soc-muted">
                      <span>Returned {labResult.count} rows</span>
                      <span className="flex items-center gap-1 text-slate-400">
                        <Clock className="w-3.5 h-3.5" />
                        {labResult.timeMs}ms execution time
                      </span>
                    </div>

                    <div className="overflow-x-auto border border-soc-border rounded max-h-96">
                      {labResult.rows.length === 0 ? (
                        <div className="py-8 text-center text-soc-muted">0 rows returned.</div>
                      ) : (
                        <table className="w-full text-left text-xs">
                          <thead className="bg-soc-raised/80 border-b border-soc-border text-[11px]">
                            <tr>
                              {Object.keys(labResult.rows[0]).map((col) => (
                                <th key={col} className="p-2 text-slate-300">
                                  {col}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-soc-border/40">
                            {labResult.rows.map((row, idx) => (
                              <tr key={idx} className="hover:bg-soc-raised/40">
                                {Object.values(row).map((val: any, cIdx) => (
                                  <td key={cIdx} className="p-2 truncate max-w-xs text-slate-300">
                                    {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="py-16 text-center text-soc-muted space-y-2">
                    <Database className="w-6 h-6 text-soc-muted mx-auto" />
                    <div>Click "Run in Lab" to execute this KQL query against the local Kusto container.</div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
