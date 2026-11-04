import React from 'react';
import { Terminal, Shield, CheckCircle2, GitBranch, Cpu, Code2, ExternalLink } from 'lucide-react';

export function AboutScreen() {
  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Hero Header */}
      <div className="p-6 rounded-soc bg-soc-surface border border-soc-border space-y-2">
        <h1 className="text-lg font-bold text-white flex items-center gap-2">
          <span>About HuntBook</span>
          <span className="text-xs px-2 py-0.5 rounded font-mono bg-blue-900/60 text-blue-300 border border-blue-700/60">
            Architecture & Philosophy
          </span>
        </h1>
        <p className="text-xs text-soc-muted leading-relaxed">
          HuntBook is an open-source, Detection-as-Code engineering project built by <strong>Yogesh Thakur</strong>. It was designed to demonstrate rigorous detection engineering, deep telemetry comprehension of Microsoft Defender XDR and Sentinel, and disciplined test automation.
        </p>
      </div>

      {/* Architectural Pillars */}
      <div className="grid grid-cols-3 gap-4">
        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-2">
          <div className="flex items-center gap-2 text-blue-400">
            <Code2 className="w-4 h-4" />
            <h3 className="text-xs font-bold text-white">Detection as Code</h3>
          </div>
          <p className="text-xs text-soc-muted leading-relaxed">
            Every hunt is a dual file contract: a pure, parameterized <code>.kql</code> query and a structured <code>.hunt.yml</code> metadata file containing hypothesis, false positive notes, and tuning guidance.
          </p>
        </div>

        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-2">
          <div className="flex items-center gap-2 text-cyan-400">
            <Cpu className="w-4 h-4" />
            <h3 className="text-xs font-bold text-white">Kusto AST Parsing</h3>
          </div>
          <p className="text-xs text-soc-muted leading-relaxed">
            Queries are parsed into Abstract Syntax Trees using Microsoft's official <code>@kusto/language-service-next</code> to verify KQL grammar and semantic column types against Defender and Sentinel schemas.
          </p>
        </div>

        <div className="p-4 rounded-soc bg-soc-surface border border-soc-border space-y-2">
          <div className="flex items-center gap-2 text-emerald-400">
            <Shield className="w-4 h-4" />
            <h3 className="text-xs font-bold text-white">Zero-Tenant Testing</h3>
          </div>
          <p className="text-xs text-soc-muted leading-relaxed">
            Eliminating the expensive cloud tenant barrier by leveraging Microsoft's local Kusto emulator container and a deterministic synthetic telemetry generator (<code>@faker-js/faker</code>).
          </p>
        </div>
      </div>

      {/* Architecture Dataflow */}
      <div className="p-5 rounded-soc bg-soc-surface border border-soc-border space-y-3">
        <h2 className="text-xs font-bold uppercase tracking-wider text-white">System Dataflow Architecture</h2>
        <div className="p-4 rounded bg-soc-app border border-soc-border font-mono text-xs text-slate-300 leading-relaxed overflow-x-auto">
          <pre>{`[hunts/**/*.kql + .hunt.yml]  ──>  [huntbook validate] (Kusto AST + Schema Check)
          │                                         │
[scenarios/*.yml]  ──>  [@huntbook/datagen]  ──>  [huntbook test] (Synthetic Test Assertions)
                                                    │
                                         [huntbook build]
                                                    │
                      ┌─────────────────────────────┼─────────────────────────────┐
                      ▼                             ▼                             ▼
               [catalog.json]               [coverage.json]             [Sentinel Rules YAML]
                      │                             │                             │
                      └─────────────────────────────┼─────────────────────────────┘
                                                    ▼
                                    [HuntBook Web Console (Vite + React)]`}</pre>
        </div>
      </div>

      {/* Tech Stack Reference */}
      <div className="p-5 rounded-soc bg-soc-surface border border-soc-border space-y-3">
        <h2 className="text-xs font-bold uppercase tracking-wider text-white">Tech Stack & Components</h2>
        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-2.5 rounded bg-soc-raised border border-soc-border">
            <span className="text-soc-muted">Monorepo:</span> <span className="text-white">pnpm workspaces + TypeScript 5</span>
          </div>
          <div className="p-2.5 rounded bg-soc-raised border border-soc-border">
            <span className="text-soc-muted">KQL Language Engine:</span> <span className="text-blue-400">@kusto/language-service-next</span>
          </div>
          <div className="p-2.5 rounded bg-soc-raised border border-soc-border">
            <span className="text-soc-muted">Synthetic Data Generator:</span> <span className="text-white">@faker-js/faker</span>
          </div>
          <div className="p-2.5 rounded bg-soc-raised border border-soc-border">
            <span className="text-soc-muted">Local KQL Execution:</span> <span className="text-blue-400">mcr.microsoft.com/.../kustainer-linux</span>
          </div>
          <div className="p-2.5 rounded bg-soc-raised border border-soc-border">
            <span className="text-soc-muted">Web Console:</span> <span className="text-white">React 18 + Vite + Tailwind CSS</span>
          </div>
          <div className="p-2.5 rounded bg-soc-raised border border-soc-border">
            <span className="text-soc-muted">Exporters:</span> <span className="text-emerald-400">Sentinel Analytics Rule YAML, ATT&CK Navigator Layer</span>
          </div>
        </div>
      </div>
    </div>
  );
}

