import React, { useState, useEffect } from 'react';
import type { CatalogData, CatalogHunt, ScreenId } from './types/index.js';
import catalogJson from './data/catalog.json';
import { LeftRail, TopBar } from './components/Navigation.js';
import { CommandPalette } from './components/CommandPalette.js';
import { OverviewScreen } from './screens/OverviewScreen.js';
import { CatalogScreen } from './screens/CatalogScreen.js';
import { HuntDetailScreen } from './screens/HuntDetailScreen.js';
import { CoverageScreen } from './screens/CoverageScreen.js';
import { ScenariosScreen } from './screens/ScenariosScreen.js';
import { ValidationScreen } from './screens/ValidationScreen.js';
import { AboutScreen } from './screens/AboutScreen.js';

export function App() {
  const data = catalogJson as unknown as CatalogData;

  const [currentScreen, setCurrentScreen] = useState<ScreenId>('overview');
  const [selectedHunt, setSelectedHunt] = useState<CatalogHunt | null>(null);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [platformFilter, setPlatformFilter] = useState('all');
  const [labStatus, setLabStatus] = useState<'online' | 'offline'>('offline');

  // Check Lab API status on mount
  useEffect(() => {
    fetch('http://127.0.0.1:3001/health')
      .then((res) => (res.ok ? res.json() : null))
      .then((json) => {
        if (json?.status === 'ok') {
          setLabStatus('online');
        }
      })
      .catch(() => setLabStatus('offline'));
  }, []);

  // Handle Hash Routing
  useEffect(() => {
    function handleHashChange() {
      const hash = window.location.hash.replace(/^#/, '');
      if (hash.startsWith('hunt/')) {
        const huntId = hash.replace('hunt/', '');
        const found = data.hunts.find((h) => h.id.toLowerCase() === huntId.toLowerCase());
        if (found) {
          setSelectedHunt(found);
          setCurrentScreen('detail');
          return;
        }
      }
      if (['overview', 'catalog', 'coverage', 'scenarios', 'validation', 'about'].includes(hash)) {
        setCurrentScreen(hash as ScreenId);
      }
    }

    handleHashChange();
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [data.hunts]);

  function navigateTo(screen: ScreenId) {
    setCurrentScreen(screen);
    window.location.hash = screen;
  }

  function handleSelectHunt(hunt: CatalogHunt) {
    setSelectedHunt(hunt);
    setCurrentScreen('detail');
    window.location.hash = `hunt/${hunt.id}`;
  }

  function handleFilterTechnique(tech: string) {
    setCurrentScreen('catalog');
    window.location.hash = 'catalog';
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-soc-app text-soc-text">
      {/* Left Rail Navigation */}
      <LeftRail
        currentScreen={currentScreen}
        onNavigate={navigateTo}
        huntCount={data.stats.huntCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <TopBar
          onOpenSearch={() => setIsSearchOpen(true)}
          platformFilter={platformFilter}
          onSetPlatformFilter={setPlatformFilter}
          labStatus={labStatus}
        />

        {/* Scrollable Viewport */}
        <main className="flex-1 overflow-y-auto p-6">
          {currentScreen === 'overview' && (
            <OverviewScreen
              data={data}
              onSelectHunt={handleSelectHunt}
              onNavigateToCatalog={() => navigateTo('catalog')}
              onNavigateToCoverage={() => navigateTo('coverage')}
            />
          )}

          {currentScreen === 'catalog' && (
            <CatalogScreen
              hunts={data.hunts}
              onSelectHunt={handleSelectHunt}
              initialPlatform={platformFilter}
            />
          )}

          {currentScreen === 'detail' && selectedHunt && (
            <HuntDetailScreen
              hunt={selectedHunt}
              onBack={() => navigateTo('catalog')}
            />
          )}

          {currentScreen === 'coverage' && (
            <CoverageScreen
              data={data}
              onFilterTechnique={handleFilterTechnique}
            />
          )}

          {currentScreen === 'scenarios' && (
            <ScenariosScreen
              scenarios={data.scenarios}
              hunts={data.hunts}
              onSelectHunt={handleSelectHunt}
            />
          )}

          {currentScreen === 'validation' && (
            <ValidationScreen
              hunts={data.hunts}
              onSelectHunt={handleSelectHunt}
            />
          )}

          {currentScreen === 'about' && <AboutScreen />}
        </main>
      </div>

      {/* Global Command Palette */}
      <CommandPalette
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        hunts={data.hunts}
        onSelectHunt={handleSelectHunt}
      />
    </div>
  );
}

