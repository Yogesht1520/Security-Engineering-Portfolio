import React, { useState, useEffect } from 'react';
import { Search, X, Terminal, ArrowRight } from 'lucide-react';
import type { CatalogHunt } from '../types/index.js';
import { SeverityBadge, ValidationBadge, PlatformBadge } from './Badges.js';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  hunts: CatalogHunt[];
  onSelectHunt: (hunt: CatalogHunt) => void;
}

export function CommandPalette({ isOpen, onClose, hunts, onSelectHunt }: CommandPaletteProps) {
  const [query, setQuery] = useState('');

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filteredHunts = hunts.filter((h) => {
    const q = query.toLowerCase();
    return (
      h.id.toLowerCase().includes(q) ||
      h.title.toLowerCase().includes(q) ||
      h.attack.techniques.some((t) => t.toLowerCase().includes(q)) ||
      h.attack.tactics.some((t) => t.toLowerCase().includes(q)) ||
      h.tables.some((tbl) => tbl.toLowerCase().includes(q))
    );
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-start justify-center pt-20 p-4">
      <div className="w-full max-w-2xl bg-soc-surface border border-soc-border rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[75vh]">
        {/* Search Input Header */}
        <div className="p-3 border-b border-soc-border flex items-center gap-2.5 bg-soc-raised/40">
          <Search className="w-4 h-4 text-soc-muted" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search hunts by ID, title, technique (e.g. T1110), or table..."
            autoFocus
            className="flex-1 bg-transparent border-none text-sm text-white placeholder-soc-muted focus:outline-none"
          />
          <button
            onClick={onClose}
            className="p-1 rounded text-soc-muted hover:text-white hover:bg-soc-raised"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="overflow-y-auto p-2 divide-y divide-soc-border/40">
          {filteredHunts.length === 0 ? (
            <div className="py-12 text-center text-xs text-soc-muted">
              No matching threat hunts found for "{query}"
            </div>
          ) : (
            filteredHunts.map((hunt) => (
              <button
                key={hunt.id}
                onClick={() => {
                  onSelectHunt(hunt);
                  onClose();
                }}
                className="w-full p-2.5 rounded-soc text-left hover:bg-soc-raised/80 transition-colors flex items-center justify-between group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-blue-400">{hunt.id}</span>
                    <span className="text-xs font-medium text-white">{hunt.title}</span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-soc-muted font-mono">
                    <span className="text-slate-400">[{hunt.attack.techniques.join(', ')}]</span>
                    <span>•</span>
                    <span>{hunt.tables.join(', ')}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <SeverityBadge severity={hunt.severity} />
                  <ArrowRight className="w-4 h-4 text-soc-muted opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              </button>
            ))
          )}
        </div>

        {/* Footer Hint */}
        <div className="p-2.5 bg-soc-raised/60 border-t border-soc-border flex items-center justify-between text-[11px] text-soc-muted">
          <span>{filteredHunts.length} of {hunts.length} hunts</span>
          <span>Press ESC to exit</span>
        </div>
      </div>
    </div>
  );
}

