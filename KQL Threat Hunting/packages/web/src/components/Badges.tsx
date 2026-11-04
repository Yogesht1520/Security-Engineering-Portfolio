import React from 'react';
import { ShieldAlert, ShieldCheck, Shield, CheckCircle2, Terminal, Cloud } from 'lucide-react';

export function SeverityBadge({ severity }: { severity: string }) {
  const sev = severity.toLowerCase();
  if (sev === 'high') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-red-950/60 text-red-400 border border-red-800/60">
        <ShieldAlert className="w-3 h-3 text-red-400" />
        High
      </span>
    );
  }
  if (sev === 'medium') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-amber-950/60 text-amber-400 border border-amber-800/60">
        <Shield className="w-3 h-3 text-amber-400" />
        Medium
      </span>
    );
  }
  if (sev === 'low') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
        <ShieldCheck className="w-3 h-3 text-emerald-400" />
        Low
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-slate-900 text-slate-300 border border-slate-750">
      Info
    </span>
  );
}

export function ValidationBadge({ level, tests }: { level: string; tests?: { passed: number; total: number } }) {
  const lvl = level.toLowerCase();
  if (lvl === 'synthetic') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-950/60 text-blue-400 border border-blue-800/60" title="Tested against synthetic attack & baseline datasets">
        <CheckCircle2 className="w-3 h-3 text-blue-400" />
        synthetic {tests ? `(${tests.passed}/${tests.total})` : ''}
      </span>
    );
  }
  if (lvl === 'tenant') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-950/60 text-emerald-400 border border-emerald-800/60" title="Verified in live Microsoft tenant">
        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
        tenant
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-800/80 text-slate-400 border border-slate-700" title="Validated against table schemas & KQL AST">
      syntax
    </span>
  );
}

export function PlatformBadge({ platform }: { platform: string }) {
  const p = platform.toLowerCase();
  if (p === 'sentinel') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-indigo-950/40 text-indigo-300 border border-indigo-800/50">
        <Cloud className="w-3 h-3" />
        Sentinel
      </span>
    );
  }
  if (p === 'defender-xdr') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-cyan-950/40 text-cyan-300 border border-cyan-800/50">
        <Terminal className="w-3 h-3" />
        Defender XDR
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-purple-950/40 text-purple-300 border border-purple-800/50">
      Both
    </span>
  );
}

