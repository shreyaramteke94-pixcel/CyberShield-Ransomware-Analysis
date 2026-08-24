import React from 'react';
import { AdminStats, UserProfile } from '../types';
import { 
  ShieldAlert, 
  Binary, 
  Radio, 
  Activity, 
  Cpu, 
  LineChart, 
  FileSearch, 
  CheckCircle2, 
  XCircle, 
  TrendingUp,
  Server,
  Database,
  Globe,
  Layers,
  Sparkles
} from 'lucide-react';

interface AdminPanelViewProps {
  adminStats: AdminStats;
  currentUser: UserProfile;
}

export const AdminPanelView: React.FC<AdminPanelViewProps> = ({
  adminStats
}) => {
  // 6 Information Cards
  const featureCards = [
    {
      id: 'feature-threat-detection',
      title: 'Threat Detection',
      desc: 'Analyzes suspicious files and activities to identify potential security threats across organizational endpoints.',
      icon: ShieldAlert,
      iconColor: 'text-[#3B82F6]'
    },
    {
      id: 'feature-malware-analysis',
      title: 'Malware Analysis',
      desc: 'Performs automated static and dynamic analysis to uncover malicious behavior, packers, and obfuscation routines.',
      icon: Binary,
      iconColor: 'text-[#22D3EE]'
    },
    {
      id: 'feature-security-intelligence',
      title: 'Security Intelligence',
      desc: 'Provides curated security insights and IOC feeds to help analysts understand emerging adversary techniques.',
      icon: Radio,
      iconColor: 'text-[#3B82F6]'
    },
    {
      id: 'feature-incident-response',
      title: 'Incident Response',
      desc: 'Enables detected threats to be prioritized, triaged, and mitigated with derived cryptographic recovery keys.',
      icon: Activity,
      iconColor: 'text-[#22C55E]'
    },
    {
      id: 'feature-sandbox-analysis',
      title: 'Sandbox Analysis',
      desc: 'Safely detonates suspicious executables in isolated hypervisor environments to capture real-time behavior.',
      icon: Cpu,
      iconColor: 'text-[#F59E0B]'
    },
    {
      id: 'feature-platform-monitoring',
      title: 'Platform Monitoring',
      desc: 'Continuously monitors analysis throughput, system health, detection accuracy, and cluster availability.',
      icon: LineChart,
      iconColor: 'text-[#3B82F6]'
    }
  ];

  // Platform Statistics
  const statsCards = [
    {
      id: 'stat-total-analyses',
      label: 'Total Analyses',
      value: adminStats.totalAnalyses.toLocaleString(),
      subtext: 'Processed files',
      icon: FileSearch,
      iconColor: 'text-[#3B82F6]'
    },
    {
      id: 'stat-successful-analyses',
      label: 'Successful Analyses',
      value: adminStats.successfulAnalyses.toLocaleString(),
      subtext: 'Complete verdicts',
      icon: CheckCircle2,
      iconColor: 'text-[#22C55E]'
    },
    {
      id: 'stat-failed-analyses',
      label: 'Failed Analyses',
      value: adminStats.failedAnalyses.toString(),
      subtext: 'Corrupted inputs',
      icon: XCircle,
      iconColor: 'text-[#EF4444]'
    },
    {
      id: 'stat-success-rate',
      label: 'Analysis Success Rate',
      value: '99.4%',
      subtext: 'High-fidelity triage',
      icon: TrendingUp,
      iconColor: 'text-[#22D3EE]'
    }
  ];

  // Platform Status Services
  const statusServices = [
    {
      id: 'srv-analysis-engine',
      name: 'Analysis Engine',
      status: 'Online',
      statusType: 'operational',
      icon: Cpu
    },
    {
      id: 'srv-sandbox-environment',
      name: 'Sandbox Environment',
      status: 'Operational',
      statusType: 'operational',
      icon: Server
    },
    {
      id: 'srv-threat-intelligence',
      name: 'Threat Intelligence',
      status: 'Connected',
      statusType: 'operational',
      icon: Globe
    },
    {
      id: 'srv-database',
      name: 'Database',
      status: 'Healthy',
      statusType: 'operational',
      icon: Database
    },
    {
      id: 'srv-api-services',
      name: 'API Services',
      status: 'Operational',
      statusType: 'operational',
      icon: Layers
    }
  ];

  return (
    <div className="space-y-6 max-w-5xl pb-12" id="cybershield-about-page">
      {/* 1. Header & Platform Overview */}
      <div className="p-6 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-[#16243A] text-[#22D3EE] border border-[#24344D] text-[10px] font-medium">
            Platform Overview
          </span>
          <span className="text-[#94A3B8] text-xs font-mono">Enterprise Architecture v4.8</span>
        </div>

        <div>
          <h1 className="text-xl font-semibold text-[#F8FAFC]">
            About CyberShield
          </h1>
          <p className="text-xs text-[#3B82F6] font-medium mt-0.5">
            Intelligent security analysis and threat detection platform
          </p>
        </div>

        <p className="text-xs sm:text-sm text-[#94A3B8] leading-relaxed max-w-3xl pt-1">
          CyberShield is an intelligent cybersecurity platform designed to analyze suspicious files, 
          identify potential threats, monitor security activity, and help security teams respond to incidents efficiently.
        </p>
      </div>

      {/* 2. About CyberShield Information (6 Cards) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#3B82F6]" />
            <span>Core Capabilities &amp; Architecture</span>
          </h2>
          <span className="text-[11px] text-[#94A3B8]">6 Automated Modules</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {featureCards.map((card) => {
            const Icon = card.icon;
            return (
              <div
                key={card.id}
                id={card.id}
                className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-2 hover:border-[#3B82F6]/40 transition flex flex-col justify-between"
              >
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-[#16243A] border border-[#24344D]">
                    <Icon className={`w-4 h-4 ${card.iconColor}`} />
                  </div>
                  <h3 className="text-xs font-semibold text-[#F8FAFC]">
                    {card.title}
                  </h3>
                </div>

                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  {card.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. Platform Statistics (Compact Overview) */}
      <div className="space-y-3 pt-1">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
          Platform Statistics
        </h2>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {statsCards.map((stat) => {
            const Icon = stat.icon;
            return (
              <div
                key={stat.id}
                id={stat.id}
                className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[#94A3B8] font-medium truncate">
                    {stat.label}
                  </span>
                  <Icon className={`w-4 h-4 ${stat.iconColor}`} />
                </div>
                <div>
                  <div className="text-xl font-bold text-[#F8FAFC] tracking-tight">
                    {stat.value}
                  </div>
                  <div className="text-[11px] text-[#94A3B8] mt-0.5">
                    {stat.subtext}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 4. Platform System Status */}
      <div className="space-y-3 pt-1">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
            Platform Status
          </h2>
          <span className="text-[11px] text-[#22C55E] flex items-center gap-1.5 font-medium">
            <span className="w-2 h-2 rounded-full bg-[#22C55E]" />
            All Systems Operational
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
          {statusServices.map((srv) => {
            const Icon = srv.icon;
            const isOperational = srv.statusType === 'operational';
            return (
              <div
                key={srv.id}
                id={srv.id}
                className="p-3.5 rounded-xl bg-[#111C2E] border border-[#24344D] flex flex-col justify-between space-y-2"
              >
                <div className="flex items-center gap-2">
                  <Icon className="w-4 h-4 text-[#3B82F6]" />
                  <span className="text-[#F8FAFC] font-medium truncate">{srv.name}</span>
                </div>

                <div className="flex items-center justify-between pt-1 border-t border-[#24344D]/60 text-[11px]">
                  <span className="text-[#94A3B8]">Status</span>
                  <span className={`font-medium flex items-center gap-1 ${
                    isOperational ? 'text-[#22C55E]' : 'text-[#F59E0B]'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${isOperational ? 'bg-[#22C55E]' : 'bg-[#F59E0B]'}`} />
                    {srv.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
