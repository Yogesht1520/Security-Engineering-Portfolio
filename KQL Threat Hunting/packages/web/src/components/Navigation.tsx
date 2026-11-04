import React from 'react';
import {
  LayoutDashboard,
  Search,
  ShieldAlert,
  PlaySquare,
  CheckCircle,
  Info,
  Github,
  Layers,
  Terminal,
  Filter
} from 'lucide-react';
import type { ScreenId } from '../types/index.js';

interface LeftRailProps {
  currentScreen: ScreenId;
  onNavigate: (screen: ScreenId) => void;
  huntCount: number;
}

export function LeftRail({ currentScreen, onNavigate, huntCount }: LeftRailProps) {
  const navItems: Array<{ id: ScreenId; label: string; icon: React.ComponentType<{ className?: string }>; badge?: number }> = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'catalog', label: 'Hunt Catalog', icon: Terminal, badge: huntCount },
    { id: 'coverage', label: 'ATT&CK Coverage', icon: Layers },
    { id: 'scenarios', label: 'Scenario Replay', icon: PlaySquare },
    { id: 'validation', label: 'Validation Health', icon: CheckCircle },
    { id: 'about', label: 'About & Arch', icon: Info }
  ];

  return (
    <aside className="w-64 bg-soc-surface border-r border-soc-border flex flex-col justify-between select-none">
      <div>
        {/* Brand Header */}
        <div className="h-14 px-5 flex items-center gap-3 border-b border-soc-border">
          <div className="w-7 h-7 rounded-md bg-blue-600 flex items-center justify-center text-white font-bold text-sm shadow-md shadow-blue-500/20">
            HB
          </div>
          <div>
            <div className="font-bold text-sm tracking-wide text-white flex items-center gap-1.5">
              HuntBook
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-900/60 text-blue-300 border border-blue-700/50">
                v1.0
              </span>
            </div>
            <div className="text-[11px] text-soc-muted">KQL Detection Engine</div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentScreen === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-soc text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                    : 'text-soc-muted hover:text-soc-text hover:bg-soc-raised/60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-soc-muted'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="px-1.5 py-0.2 rounded font-mono text-[10px] bg-soc-raised border border-soc-border text-soc-muted">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-soc-border bg-soc-surface/50">
        <div className="text-[11px] text-soc-muted">Author: Yogesh Thakur</div>
        <div className="text-[10px] text-slate-500 font-mono mt-0.5">Detection-as-Code Library</div>
      </div>
    </aside>
  );
}

interface TopBarProps {
  onOpenSearch: () => void;
  platformFilter: string;
  onSetPlatformFilter: (p: string) => void;
  labStatus?: 'online' | 'offline';
}

export function TopBar({ onOpenSearch, platformFilter, onSetPlatformFilter, labStatus = 'offline' }: TopBarProps) {
  return (
    <header className="h-14 px-6 bg-soc-surface/80 backdrop-blur border-b border-soc-border flex items-center justify-between">
      {/* Quick Search Button */}
      <button
        onClick={onOpenSearch}
        className="flex items-center gap-2 px-3 py-1.5 rounded-soc bg-soc-raised border border-soc-border text-xs text-soc-muted hover:text-soc-text hover:border-slate-600 transition-colors w-72"
      >
        <Search className="w-3.5 h-3.5" />
        <span className="flex-1 text-left">Quick Search Hunts...</span>
        <kbd className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-soc-surface border border-soc-border text-slate-400">
          Ctrl K
        </kbd>
      </button>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Platform Selector */}
        <div className="flex items-center rounded-soc bg-soc-raised p-0.5 border border-soc-border text-xs">
          {['all', 'sentinel', 'defender-xdr'].map((p) => (
            <button
              key={p}
              onClick={() => onSetPlatformFilter(p)}
              className={`px-2.5 py-1 rounded text-xs transition-colors ${
                platformFilter === p
                  ? 'bg-blue-600 text-white font-medium shadow-sm'
                  : 'text-soc-muted hover:text-soc-text'
              }`}
            >
              {p === 'all' ? 'All Platforms' : p === 'sentinel' ? 'Sentinel' : 'Defender XDR'}
            </button>
          ))}
        </div>

        {/* Lab Runtime Indicator */}
        <div
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-soc border text-xs font-mono ${
            labStatus === 'online'
              ? 'bg-blue-950/40 border-blue-800/50 text-blue-400'
              : 'bg-slate-900 border-soc-border text-slate-500'
          }`}
          title={labStatus === 'online' ? 'Local Kusto emulator ready for query execution' : 'Lab offline (run docker compose up -d to enable)'}
        >
          <span className={`w-2 h-2 rounded-full ${labStatus === 'online' ? 'bg-blue-400 animate-pulse' : 'bg-slate-600'}`}></span>
          {labStatus === 'online' ? 'Lab: Ready' : 'Lab: Offline'}
        </div>

        {/* Status indicator */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-soc bg-emerald-950/40 border border-emerald-800/50 text-emerald-400 text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          CI Passing
        </div>

        {/* GitHub link */}
        <a
          href="https://github.com/yogesh-thakur"
          target="_blank"
          rel="noreferrer"
          className="p-1.5 rounded-soc text-soc-muted hover:text-white hover:bg-soc-raised transition-colors"
          title="GitHub Repository"
        >
          <Github className="w-4 h-4" />
        </a>
      </div>
    </header>
  );
}

