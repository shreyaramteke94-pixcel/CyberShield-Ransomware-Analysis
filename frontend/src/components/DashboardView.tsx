import React from 'react';
import { SampleAnalysis, AdminStats } from '../types';
import { MOCK_CHART_DATA } from '../data/mockData';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Plus, 
  Radio, 
  ArrowUpRight, 
  Key, 
  CheckCircle2, 
  XCircle, 
  Shield, 
  Server, 
  AlertTriangle,
  PieChart as PieIcon,
  TrendingUp,
  Unlock
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Legend 
} from 'recharts';

interface DashboardViewProps {
  samples: SampleAnalysis[];
  adminStats: AdminStats;
  onSelectSample: (sample: SampleAnalysis) => void;
  onNavigate: (tab: string) => void;
  onOpenDecryptor: (sample: SampleAnalysis) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  samples,
  adminStats,
  onSelectSample,
  onNavigate,
  onOpenDecryptor
}) => {
  // 4 Core Security Overview Summary Cards
  const overviewCards = [
    {
      id: 'card-security-status',
      label: 'Security Status',
      value: 'Protected',
      subtext: 'Optimal · Monitoring Active',
      statusColor: 'text-[#22C55E]',
      icon: ShieldCheck,
      iconColor: 'text-[#22C55E]',
      badge: 'Normal'
    },
    {
      id: 'card-active-threats',
      label: 'Active Threats',
      value: '3',
      subtext: 'Critical · High Severity',
      statusColor: 'text-[#EF4444]',
      icon: ShieldAlert,
      iconColor: 'text-[#EF4444]',
      badge: 'Action Required'
    },
    {
      id: 'card-systems-protected',
      label: 'Systems Protected',
      value: '256',
      subtext: '100% active coverage',
      statusColor: 'text-[#22D3EE]',
      icon: Shield,
      iconColor: 'text-[#22D3EE]',
      badge: 'Verified'
    },
    {
      id: 'card-failed-analyses',
      label: 'Failed Analyses',
      value: adminStats.failedAnalyses.toString(),
      subtext: '0.6% error rate',
      statusColor: 'text-[#94A3B8]',
      icon: XCircle,
      iconColor: 'text-[#94A3B8]',
      badge: 'Low'
    }
  ];

  return (
    <div className="space-y-6 pb-12" id="cybershield-dashboard-view">
      {/* 1. Header & Primary Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 p-5 rounded-xl bg-[#111C2E] border border-[#24344D]">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold text-[#F8FAFC]">Security Dashboard</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-[#16243A] text-[#22D3EE] border border-[#24344D]">
              Console Live
            </span>
          </div>
          <p className="text-xs text-[#94A3B8] mt-0.5">
            Automated malware detonation, behavioral heuristics, and active endpoint protection
          </p>
        </div>

        {/* Primary and Secondary Actions */}
        <div className="flex items-center gap-2.5">
          <button
            id="dash-quick-scan-btn"
            onClick={() => onNavigate('upload')}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-xs transition shadow-sm cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>+ Quick Scan</span>
          </button>

          <button
            id="dash-threat-intel-btn"
            onClick={() => onNavigate('threat-intel')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#16243A] hover:bg-[#24344D] border border-[#24344D] text-[#F8FAFC] text-xs font-medium transition cursor-pointer"
          >
            <Radio className="w-3.5 h-3.5 text-[#22D3EE]" />
            <span>Threat Intelligence</span>
          </button>
        </div>
      </div>

      {/* 2. System Status Bar */}
      <div className="p-3.5 rounded-xl bg-[#16243A] border border-[#24344D] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2.5">
          <span className="w-2 h-2 rounded-full bg-[#22C55E] flex-shrink-0 animate-pulse" />
          <span className="text-[#F8FAFC] font-medium">Security Engine: Active</span>
          <span className="text-[#24344D]">|</span>
          <span className="text-[#94A3B8]">Signatures: Updated</span>
          <span className="text-[#24344D] hidden md:inline">|</span>
          <span className="text-[#94A3B8] hidden md:inline">DeepMalwareNet v4.8 Active Heuristics</span>
        </div>

        <div className="flex items-center gap-3 text-[11px] font-mono text-[#94A3B8]">
          <span className="flex items-center gap-1">
            <Server className="w-3 h-3 text-[#3B82F6]" /> 8 Sandbox Nodes
          </span>
          <span className="text-[#24344D]">|</span>
          <span className="text-[#22C55E]">All Systems Operational</span>
        </div>
      </div>

      {/* 3. Security Overview Cards (Focused 4 Core Metrics) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {overviewCards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.id}
              id={card.id}
              className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] flex flex-col justify-between space-y-2 hover:border-[#3B82F6]/40 transition"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#94A3B8] font-medium uppercase tracking-wider">
                  {card.label}
                </span>
                <div className="p-1.5 rounded-lg bg-[#16243A] border border-[#24344D]">
                  <Icon className={`w-4 h-4 ${card.iconColor}`} />
                </div>
              </div>

              <div>
                <div className="text-2xl font-bold text-[#F8FAFC] tracking-tight">{card.value}</div>
                <div className="flex items-center justify-between text-[11px] mt-1">
                  <span className={card.statusColor}>{card.subtext}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* 4. Threat Distribution & Monthly Detonation Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Threat Distribution Chart (Categories visualization) */}
        <div className="lg:col-span-5 p-5 rounded-xl bg-[#111C2E] border border-[#24344D] flex flex-col justify-between space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] flex items-center gap-1.5">
              <PieIcon className="w-3.5 h-3.5 text-[#22D3EE]" />
              <span>Threat Distribution</span>
            </h2>
            <span className="text-[11px] font-mono text-[#94A3B8]">Classifications</span>
          </div>

          <div className="h-44 w-full relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={MOCK_CHART_DATA.familyDistribution}
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={3}
                  dataKey="count"
                >
                  {MOCK_CHART_DATA.familyDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#111C2E" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111C2E', borderColor: '#24344D', borderRadius: '8px', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-[10px] text-[#94A3B8]">Primary Threat</span>
              <span className="text-xs font-bold text-[#EF4444]">LockBit 3.0</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[11px] pt-2 border-t border-[#24344D]">
            {MOCK_CHART_DATA.familyDistribution.map((f) => (
              <div key={f.name} className="flex items-center justify-between text-[#94A3B8] pr-1">
                <span className="flex items-center gap-1.5 truncate">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: f.color }} />
                  <span className="truncate">{f.name}</span>
                </span>
                <span className="font-mono text-[#F8FAFC]">{f.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Activity & Detonation Trend Area Chart */}
        <div className="lg:col-span-7 p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] flex items-center gap-1.5">
              <TrendingUp className="w-3.5 h-3.5 text-[#3B82F6]" />
              <span>Threat Activity &amp; Detonation Trend</span>
            </h2>
            <span className="text-[11px] font-mono text-[#94A3B8]">Monthly Timeline</span>
          </div>

          <div className="h-48 w-full pt-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={MOCK_CHART_DATA.monthlyTrend} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorIngested" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorNeutralized" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22C55E" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#22C55E" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#24344D" vertical={false} />
                <XAxis dataKey="month" stroke="#94A3B8" tick={{ fontSize: 11 }} />
                <YAxis stroke="#94A3B8" tick={{ fontSize: 11 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111C2E', borderColor: '#24344D', borderRadius: '8px', fontSize: '12px' }} 
                  itemStyle={{ color: '#F8FAFC' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '4px' }} />
                <Area type="monotone" dataKey="samples" name="Total Ingested" stroke="#3B82F6" strokeWidth={1.5} fill="url(#colorIngested)" />
                <Area type="monotone" dataKey="detected" name="Threats Detected" stroke="#EF4444" strokeWidth={1.5} fill="url(#colorThreats)" />
                <Area type="monotone" dataKey="decrypted" name="Neutralized / Cleaned" stroke="#22C55E" strokeWidth={1.5} fill="url(#colorNeutralized)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 5. Recent Security Alerts & Analyses Table */}
      <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3.5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-[#F8FAFC]">Recent Security Alerts &amp; Analyses</h2>
            <p className="text-xs text-[#94A3B8]">Latest file submissions, malware classifications, and incident verdicts</p>
          </div>

          <button
            onClick={() => onNavigate('results')}
            className="flex items-center gap-1 text-xs text-[#3B82F6] hover:underline font-medium self-start sm:self-auto cursor-pointer"
          >
            <span>View all analyses ({samples.length})</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs" id="recent-samples-table">
            <thead>
              <tr className="border-b border-[#24344D] text-[#94A3B8] text-[11px] uppercase bg-[#16243A]">
                <th className="py-2.5 px-3 font-medium">Sample / Payload</th>
                <th className="py-2.5 px-3 font-medium">Verdict</th>
                <th className="py-2.5 px-3 font-medium">Threat Level</th>
                <th className="py-2.5 px-3 font-medium">Classification</th>
                <th className="py-2.5 px-3 font-medium">Status</th>
                <th className="py-2.5 px-3 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#24344D]/60 font-mono">
              {samples.map((sample) => {
                const isMalicious = sample.verdict === 'MALICIOUS';
                const isSafe = sample.verdict === 'SAFE';

                return (
                  <tr 
                    key={sample.id} 
                    className="hover:bg-[#16243A] transition cursor-pointer"
                    onClick={() => onSelectSample(sample)}
                  >
                    <td className="py-3 px-3">
                      <div>
                        <div className="font-medium text-[#F8FAFC] font-sans truncate max-w-[200px]">{sample.fileName}</div>
                        <div className="text-[10px] text-[#94A3B8] truncate max-w-[180px]">{sample.sha256.substring(0, 16)}...</div>
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium ${
                        isMalicious 
                          ? 'bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30' 
                          : isSafe 
                          ? 'bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30' 
                          : 'bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30'
                      }`}>
                        {isMalicious ? <XCircle className="w-3 h-3" /> : isSafe ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                        {sample.verdict}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`text-[11px] font-medium ${
                        sample.threatLevel === 'CRITICAL' ? 'text-[#EF4444]' :
                        sample.threatLevel === 'HIGH' ? 'text-[#F59E0B]' :
                        sample.threatLevel === 'SAFE' ? 'text-[#22C55E]' : 'text-[#94A3B8]'
                      }`}>
                        {sample.threatLevel}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <span className="text-[#F8FAFC] font-sans text-xs">
                        {sample.ransomwareFamily}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      {sample.decryptionStatus === 'DECRYPTABLE' ? (
                        <span className="text-[#22C55E] text-[11px] font-medium flex items-center gap-1">
                          <Unlock className="w-3 h-3" /> Decryptable
                        </span>
                      ) : sample.decryptionStatus === 'UNSUPPORTED' ? (
                        <span className="text-[#94A3B8] text-[11px]">Unreversible</span>
                      ) : (
                        <span className="text-[#94A3B8] text-[11px]">Verified Safe</span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        {sample.decryptionStatus === 'DECRYPTABLE' && (
                          <button
                            onClick={() => onOpenDecryptor(sample)}
                            className="px-2 py-1 rounded bg-[#3B82F6] hover:bg-blue-600 text-white text-[10px] font-medium flex items-center gap-1 transition cursor-pointer"
                            title="Launch Decryptor Workbench"
                          >
                            <Key className="w-3 h-3" />
                            Decrypt
                          </button>
                        )}
                        <button
                          onClick={() => onSelectSample(sample)}
                          className="p-1 rounded hover:bg-[#24344D] text-[#94A3B8] hover:text-[#F8FAFC] transition cursor-pointer"
                          title="Inspect Details"
                        >
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
