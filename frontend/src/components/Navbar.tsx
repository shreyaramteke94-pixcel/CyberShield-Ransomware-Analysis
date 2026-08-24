import React, { useState } from 'react';
import { CyberLogo } from './CyberLogo';
import { 
  Bell, 
  ChevronDown, 
  LogOut, 
  Settings, 
  Info, 
  ShieldCheck,
  ShieldAlert,
  User,
  LayoutDashboard,
  Shield,
  Radio,
  FileText
} from 'lucide-react';

interface NavbarProps {
  onNavigate: (tab: string) => void;
  onLogout: () => void;
  activeTab: string;
  totalSamples: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  onNavigate,
  onLogout,
  activeTab,
  totalSamples
}) => {
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  const navLinks = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'results', label: 'Security', icon: Shield },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Radio },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  const notifications = [
    { id: '1', title: 'Critical Ransomware Analyzed', desc: 'LockBit 3.0 payload decrypted successfully', time: '10m ago', type: 'critical' },
    { id: '2', title: 'YARA Signatures Updated', desc: 'Loaded 42 new rules for Akira & Babuk', time: '45m ago', type: 'info' },
    { id: '3', title: 'Cluster Status: Healthy', desc: 'Detonation sandbox nodes operational', time: '2h ago', type: 'success' }
  ];

  return (
    <header className="sticky top-0 z-40 w-full bg-[#0B1220] border-b border-[#24344D]" id="cybershield-navbar">
      {/* Sleek single-line operational status bar */}
      <div className="bg-[#111C2E] border-b border-[#24344D]/70 px-4 sm:px-8 py-1 text-[11px] flex items-center justify-between text-[#94A3B8]">
        <div className="flex items-center gap-2 overflow-hidden">
          <span className="w-2 h-2 rounded-full bg-[#22C55E]" />
          <span className="text-[#F8FAFC] font-medium">Security Engine: Active</span>
          <span className="text-[#24344D]">|</span>
          <span className="text-[#94A3B8]">Signatures: Updated</span>
          <span className="text-[#24344D] hidden md:inline">|</span>
          <span className="truncate text-[#94A3B8] hidden md:inline">Live Threat Detection &amp; Automated Sandbox Active</span>
        </div>
        <div className="hidden sm:flex items-center gap-3 text-[11px] font-mono">
          <span className="text-[#22C55E]">Protected</span>
          <span className="text-[#24344D]">|</span>
          <span className="text-[#3B82F6]">{totalSamples} Samples Analyzed</span>
        </div>
      </div>

      {/* Main Navbar Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-4">
        {/* Brand Logo */}
        <div 
          className="cursor-pointer flex items-center" 
          onClick={() => onNavigate('dashboard')}
          id="navbar-brand"
        >
          <CyberLogo size="md" showSubtitle={false} />
        </div>

        {/* Main Navigation Items */}
        <nav className="hidden md:flex items-center gap-1">
          {navLinks.map((link) => {
            const Icon = link.icon;
            const isActive = activeTab === link.id || (link.id === 'results' && (activeTab === 'results' || activeTab === 'upload'));
            return (
              <button
                key={link.id}
                id={`nav-link-${link.id}`}
                onClick={() => onNavigate(link.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                  isActive
                    ? 'bg-[#16243A] text-[#22D3EE] border border-[#24344D]'
                    : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#111C2E]'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-[#22D3EE]' : 'text-[#94A3B8]'}`} />
                <span>{link.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Right Actions: Notification + Generic Account Dropdown */}
        <div className="flex items-center gap-3">
          {/* Notifications Toggle */}
          <div className="relative">
            <button
              id="nav-notifications-toggle"
              onClick={() => {
                setShowNotifications(!showNotifications);
                setShowUserMenu(false);
              }}
              className="relative p-2 rounded-lg bg-[#111C2E] border border-[#24344D] hover:bg-[#16243A] text-[#94A3B8] hover:text-[#F8FAFC] transition cursor-pointer"
              title="System Alerts"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-[#3B82F6] rounded-full" />
            </button>

            {/* Notifications Dropdown */}
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 rounded-xl bg-[#111C2E] border border-[#24344D] shadow-xl p-3 z-50 animate-in fade-in">
                <div className="flex items-center justify-between pb-2.5 border-b border-[#24344D] mb-2.5">
                  <div className="flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-[#3B82F6]" />
                    <span className="text-xs font-semibold text-[#F8FAFC]">System Alerts</span>
                  </div>
                  <span className="text-[10px] font-mono text-[#3B82F6] bg-[#16243A] px-2 py-0.5 rounded border border-[#24344D]">
                    Live
                  </span>
                </div>
                <div className="space-y-2">
                  {notifications.map((n) => (
                    <div key={n.id} className="p-2 rounded-lg bg-[#16243A] border border-[#24344D] hover:border-[#3B82F6]/50 transition">
                      <div className="flex items-center justify-between text-xs">
                        <span className={`font-medium ${n.type === 'critical' ? 'text-[#EF4444]' : n.type === 'success' ? 'text-[#22C55E]' : 'text-[#3B82F6]'}`}>
                          {n.title}
                        </span>
                        <span className="text-[10px] font-mono text-[#94A3B8]">{n.time}</span>
                      </div>
                      <p className="text-[11px] text-[#94A3B8] mt-0.5">{n.desc}</p>
                    </div>
                  ))}
                </div>
                <button
                  onClick={() => {
                    setShowNotifications(false);
                    onNavigate('threat-intel');
                  }}
                  className="w-full mt-2.5 pt-2 text-center text-xs text-[#3B82F6] hover:underline font-medium border-t border-[#24344D] block cursor-pointer"
                >
                  View Threat Intelligence →
                </button>
              </div>
            )}
          </div>

          {/* Simple Generic Account Dropdown */}
          <div className="relative">
            <button
              id="nav-account-btn"
              onClick={() => {
                setShowUserMenu(!showUserMenu);
                setShowNotifications(false);
              }}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#111C2E] border border-[#24344D] hover:bg-[#16243A] text-[#F8FAFC] text-xs font-medium transition cursor-pointer"
            >
              <div className="w-5 h-5 rounded-md bg-[#16243A] border border-[#24344D] flex items-center justify-center text-[#3B82F6]">
                <User className="w-3.5 h-3.5" />
              </div>
              <span>Admin Account</span>
              <ChevronDown className="w-3.5 h-3.5 text-[#94A3B8]" />
            </button>

            {/* Account Menu Dropdown */}
            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-52 rounded-xl bg-[#111C2E] border border-[#24344D] shadow-xl p-2 z-50 animate-in fade-in">
                <div className="p-2 border-b border-[#24344D] mb-1">
                  <div className="text-xs font-semibold text-[#F8FAFC] flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-[#22C55E]" />
                    <span>Security Administrator</span>
                  </div>
                  <div className="text-[11px] text-[#94A3B8] font-mono mt-0.5">admin@cybershield.sec</div>
                </div>

                <div className="space-y-0.5">
                  <button
                    onClick={() => {
                      setShowUserMenu(false);
                      onNavigate('admin');
                    }}
                    className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#16243A] transition text-left cursor-pointer"
                  >
                    <Info className="w-3.5 h-3.5 text-[#3B82F6]" />
                    About CyberShield
                  </button>

                  <button
                    onClick={() => {
                      setShowUserMenu(false);
                      onNavigate('settings');
                    }}
                    className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#16243A] transition text-left cursor-pointer"
                  >
                    <Settings className="w-3.5 h-3.5 text-[#3B82F6]" />
                    Platform Settings
                  </button>
                </div>

                <div className="pt-1 mt-1 border-t border-[#24344D]">
                  <button
                    id="nav-logout-btn"
                    onClick={() => {
                      setShowUserMenu(false);
                      onLogout();
                    }}
                    className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs text-[#EF4444] hover:bg-[#16243A] transition text-left cursor-pointer"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
