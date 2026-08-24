import React from 'react';
import { 
  LayoutDashboard, 
  Scan, 
  FileSearch, 
  Radio, 
  FileText, 
  Info, 
  Settings, 
  ChevronRight,
  Cpu,
  Database
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  onNavigate: (tab: string) => void;
  onLogout: () => void;
  analysesCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onNavigate,
  analysesCount
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'upload', label: 'Quick Scan', icon: Scan },
    { id: 'results', label: 'Analysis Results', icon: FileSearch, badge: analysesCount.toString() },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Radio },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'admin', label: 'Administration', icon: Info },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-60 flex-shrink-0 bg-[#0B1220] border-r border-[#24344D] flex flex-col justify-between h-[calc(100vh-3.5rem)] sticky top-14 select-none" id="cybershield-sidebar">
      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[11px] font-semibold text-[#94A3B8]/80 uppercase tracking-wider">
          Platform Menu
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`sidebar-nav-${item.id}`}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 text-xs font-medium rounded-lg transition ${
                isActive
                  ? 'text-[#F8FAFC] bg-[#16243A] border-l-2 border-[#3B82F6]'
                  : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#111C2E]'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-[#3B82F6]' : 'text-[#94A3B8]'}`} />
                <span className="truncate">{item.label}</span>
              </div>

              <div className="flex items-center gap-1.5">
                {item.badge && (
                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                    isActive ? 'bg-[#3B82F6] text-white' : 'bg-[#16243A] text-[#94A3B8] border border-[#24344D]'
                  }`}>
                    {item.badge}
                  </span>
                )}
                {isActive && <ChevronRight className="w-3.5 h-3.5 text-[#3B82F6]" />}
              </div>
            </button>
          );
        })}
      </nav>

      {/* Sidebar Footer: System Status */}
      <div className="p-3 border-t border-[#24344D] bg-[#0B1220] space-y-2">
        <div className="p-2.5 rounded-lg bg-[#111C2E] border border-[#24344D] space-y-2 text-xs">
          <div className="flex items-center justify-between text-[11px] text-[#94A3B8]">
            <span className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-[#3B82F6]" /> Sandbox Engine
            </span>
            <span className="text-[#22C55E] font-medium font-mono">Operational</span>
          </div>

          <div className="w-full bg-[#16243A] h-1.5 rounded-full overflow-hidden">
            <div className="bg-[#3B82F6] h-full w-[18%] rounded-full" />
          </div>

          <div className="flex items-center justify-between text-[11px] text-[#94A3B8] pt-0.5">
            <span className="flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-[#22D3EE]" /> Threat DB
            </span>
            <span className="text-[#22C55E] text-[10px] font-medium">Connected</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
