import React from 'react';
import { MOCK_CHART_DATA } from '../data/mockData';
import { 
  TrendingUp, 
  Key, 
  Layers, 
  Zap, 
  Clock, 
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  BarChart, 
  Bar 
} from 'recharts';

export const AnalyticsView: React.FC = () => {
  return (
    <div className="space-y-6 pb-12" id="cybershield-analytics-view">
      {/* Header */}
      <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D]">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h1 className="text-xl font-semibold text-[#F8FAFC]">
              Threat Analytics
            </h1>
            <p className="text-xs text-[#94A3B8] mt-0.5">
              Aggregated ransomware metrics, cryptographic cipher distribution, and MITRE ATT&amp;CK mapping.
            </p>
          </div>
          <div className="text-xs text-[#94A3B8] font-mono">
            Updated: Real-time
          </div>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <div className="flex items-center justify-between text-xs text-[#94A3B8]">
            <span>Avg. Latency</span>
            <Clock className="w-3.5 h-3.5 text-[#3B82F6]" />
          </div>
          <div className="text-xl font-semibold text-[#F8FAFC]">4.2s</div>
          <div className="text-[11px] text-[#22C55E]">16-core Baremetal Sandbox</div>
        </div>

        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <div className="flex items-center justify-between text-xs text-[#94A3B8]">
            <span>Decryption Rate</span>
            <Key className="w-3.5 h-3.5 text-[#3B82F6]" />
          </div>
          <div className="text-xl font-semibold text-[#3B82F6]">41.8%</div>
          <div className="text-[11px] text-[#94A3B8]">518 strains reversible</div>
        </div>

        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <div className="flex items-center justify-between text-xs text-[#94A3B8]">
            <span>Top Cipher</span>
            <Zap className="w-3.5 h-3.5 text-[#F59E0B]" />
          </div>
          <div className="text-lg font-semibold text-[#F8FAFC]">AES-256-CBC</div>
          <div className="text-[11px] text-[#94A3B8]">46% of observed strains</div>
        </div>

        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <div className="flex items-center justify-between text-xs text-[#94A3B8]">
            <span>Top Technique</span>
            <Layers className="w-3.5 h-3.5 text-[#EF4444]" />
          </div>
          <div className="text-lg font-semibold text-[#EF4444]">T1486 (Encrypt)</div>
          <div className="text-[11px] text-[#94A3B8]">894 signatures mapped</div>
        </div>
      </div>

      {/* Main Area Chart: Monthly Trend */}
      <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] flex items-center gap-2">
              <TrendingUp className="w-3.5 h-3.5 text-[#3B82F6]" />
              Monthly Activity &amp; Decryption Rates
            </h2>
            <p className="text-xs text-[#94A3B8] mt-0.5">Monthly breakdown of analyzed files, detected ransomware, and reconstructed decryptors</p>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={MOCK_CHART_DATA.monthlyTrend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="areaTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="areaDetected" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="areaDecrypted" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22C55E" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#22C55E" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#24344D" vertical={false} />
              <XAxis dataKey="month" stroke="#94A3B8" tick={{ fontSize: 11 }} />
              <YAxis stroke="#94A3B8" tick={{ fontSize: 11 }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#16243A', borderColor: '#24344D', borderRadius: '8px', fontSize: '12px', color: '#F8FAFC' }} 
                itemStyle={{ color: '#F8FAFC' }}
              />
              <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
              <Area type="monotone" dataKey="samples" name="Total Ingested" stroke="#3B82F6" strokeWidth={1.5} fill="url(#areaTotal)" />
              <Area type="monotone" dataKey="detected" name="Ransomware Confirmed" stroke="#EF4444" strokeWidth={1.5} fill="url(#areaDetected)" />
              <Area type="monotone" dataKey="decrypted" name="Keys Recovered" stroke="#22C55E" strokeWidth={1.5} fill="url(#areaDecrypted)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 2-Column: MITRE ATT&CK Techniques & Encryption Algorithms */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* MITRE Techniques Bar Chart */}
        <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-[#3B82F6]" />
            Observed MITRE ATT&amp;CK Tactics
          </h2>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={MOCK_CHART_DATA.mitreDistribution} layout="vertical" margin={{ top: 5, right: 15, left: 30, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#24344D" horizontal={false} />
                <XAxis type="number" stroke="#94A3B8" tick={{ fontSize: 10 }} />
                <YAxis dataKey="tactic" type="category" stroke="#94A3B8" tick={{ fontSize: 10 }} width={120} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#16243A', borderColor: '#24344D', borderRadius: '8px', fontSize: '12px', color: '#F8FAFC' }}
                />
                <Bar dataKey="detections" fill="#3B82F6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Encryption Algorithms Share */}
        <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] flex items-center gap-2">
            <Key className="w-3.5 h-3.5 text-[#3B82F6]" />
            Encryption Cipher Distribution
          </h2>

          <div className="space-y-3 font-mono text-xs pt-1">
            {MOCK_CHART_DATA.cryptoAlgos.map((item) => (
              <div key={item.algo} className="space-y-1">
                <div className="flex items-center justify-between text-[#F8FAFC]">
                  <span>{item.algo}</span>
                  <span className="text-[#3B82F6]">{item.percentage}%</span>
                </div>
                <div className="w-full bg-[#16243A] h-1.5 rounded-full overflow-hidden">
                  <div 
                    className="bg-[#3B82F6] h-full" 
                    style={{ width: `${item.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

