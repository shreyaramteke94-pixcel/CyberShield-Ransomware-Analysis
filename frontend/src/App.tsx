import React, { useState } from 'react';
import { UserProfile, SampleAnalysis } from './types';
import { INITIAL_ADMIN_STATS, INITIAL_SAMPLES } from './data/mockData';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { UploadView } from './components/UploadView';
import { AnalysisResultsView } from './components/AnalysisResultsView';
import { ReportView } from './components/ReportView';
import { AnalyticsView } from './components/AnalyticsView';
import { ThreatIntelView } from './components/ThreatIntelView';
import { AdminPanelView } from './components/AdminPanelView';
import { SettingsView } from './components/SettingsView';
import { AuthView } from './components/AuthView';
import { DecryptionWorkbenchModal } from './components/DecryptionWorkbenchModal';

export default function App() {
  // Authentication State: default null to ensure Login Page opens first
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);
  
  // Navigation State
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  // Samples State
  const [samples, setSamples] = useState<SampleAnalysis[]>(INITIAL_SAMPLES);
  const [selectedSample, setSelectedSample] = useState<SampleAnalysis>(INITIAL_SAMPLES[0]);

  // Decryptor Modal State
  const [isDecryptorOpen, setIsDecryptorOpen] = useState(false);
  const [decryptorSample, setDecryptorSample] = useState<SampleAnalysis>(INITIAL_SAMPLES[0]);

  // Admin Stats
  const [adminStats, setAdminStats] = useState(INITIAL_ADMIN_STATS);

  // Handlers
  const handleLogin = (user: UserProfile) => {
    setCurrentUser(user);
    setActiveTab('dashboard');
  };

  const handleLogout = () => {
    setCurrentUser(null);
  };

  const handleNavigate = (tab: string) => {
    setActiveTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleSelectSample = (sample: SampleAnalysis) => {
    setSelectedSample(sample);
    setActiveTab('results');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleViewReport = (sample: SampleAnalysis) => {
    setSelectedSample(sample);
    setActiveTab('reports');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleOpenDecryptor = (sample: SampleAnalysis) => {
    setDecryptorSample(sample);
    setIsDecryptorOpen(true);
  };

  const handleAnalysisComplete = (newSample: SampleAnalysis) => {
    const exists = samples.some(s => s.id === newSample.id);
    if (!exists) {
      setSamples([newSample, ...samples]);
    }
    setSelectedSample(newSample);
    setAdminStats(prev => ({
      ...prev,
      totalAnalyses: prev.totalAnalyses + 1,
      successfulAnalyses: prev.successfulAnalyses + 1
    }));
    setActiveTab('results');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // If unauthenticated, show CyberShield Login / Auth View first
  if (!currentUser) {
    return <AuthView onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-[#0B1220] text-[#F8FAFC] flex flex-col font-sans" id="cybershield-app-root">
      {/* Top Navbar */}
      <Navbar
        currentUser={currentUser}
        onNavigate={handleNavigate}
        onLogout={handleLogout}
        activeTab={activeTab}
        totalSamples={samples.length + 1424}
      />

      {/* Main Layout Area */}
      <div className="flex-1 flex max-w-full">
        {/* Left Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onNavigate={handleNavigate}
          onLogout={handleLogout}
          analysesCount={samples.length}
        />

        {/* Content Viewport */}
        <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8 overflow-y-auto max-w-7xl mx-auto">
          {activeTab === 'dashboard' && (
            <DashboardView
              samples={samples}
              adminStats={adminStats}
              onSelectSample={handleSelectSample}
              onNavigate={handleNavigate}
              onOpenDecryptor={handleOpenDecryptor}
            />
          )}

          {activeTab === 'upload' && (
            <UploadView
              onAnalysisComplete={handleAnalysisComplete}
              existingSamples={samples}
            />
          )}

          {activeTab === 'results' && (
            <AnalysisResultsView
              sample={selectedSample}
              allSamples={samples}
              onSelectSample={(s) => setSelectedSample(s)}
              onOpenDecryptor={handleOpenDecryptor}
              onViewReport={handleViewReport}
              onNavigate={handleNavigate}
            />
          )}

          {activeTab === 'reports' && (
            <ReportView
              sample={selectedSample}
              onBack={() => setActiveTab('results')}
            />
          )}

          {activeTab === 'analytics' && (
            <AnalyticsView />
          )}

          {activeTab === 'threat-intel' && (
            <ThreatIntelView />
          )}

          {activeTab === 'admin' && (
            <AdminPanelView
              adminStats={adminStats}
              currentUser={currentUser}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView />
          )}
        </main>
      </div>

      {/* Interactive Live Decryption Workbench Modal */}
      <DecryptionWorkbenchModal
        sample={decryptorSample}
        isOpen={isDecryptorOpen}
        onClose={() => setIsDecryptorOpen(false)}
      />
    </div>
  );
}
