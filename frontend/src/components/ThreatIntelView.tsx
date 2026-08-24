import React, { useState } from 'react';
import { RECENT_THREAT_FEEDS } from '../data/mockData';
import { 
  Search, 
  Check, 
  Filter 
} from 'lucide-react';

export const ThreatIntelView: React.FC = () => {
  const [searchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  // Quick IOC Lookup state
  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupResult, setLookupResult] = useState<{
    found: boolean;
    family?: string;
    verdict?: string;
    cve?: string;
    firstSeen?: string;
    ips?: string[];
  } | null>(null);

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupQuery.trim()) return;

    const q = lookupQuery.toLowerCase();
    if (q.includes('lockbit') || q.includes('7d8b') || q.includes('9f86')) {
      setLookupResult({
        found: true,
        family: 'LockBit 3.0 (Black)',
        verdict: 'MALICIOUS (High Confidence)',
        cve: 'CVE-2026-38291',
        firstSeen: '2026-08-18',
        ips: ['185.220.101.5', '194.26.29.112']
      });
    } else if (q.includes('wannacry') || q.includes('84c8') || q.includes('ms17')) {
      setLookupResult({
        found: true,
        family: 'WannaCry 2.0 (WanaCrypt0r)',
        verdict: 'MALICIOUS (SMB Worm)',
        cve: 'CVE-2017-0144 (MS17-010)',
        firstSeen: '2017-05-12',
        ips: ['198.51.100.24']
      });
    } else {
      setLookupResult({
        found: true,
        family: 'Akira / Phobos Variant Hash',
        verdict: 'SUSPICIOUS (Ransomware Heuristics)',
        cve: 'CVE-2025-41902',
        firstSeen: '2026-08-19',
        ips: ['45.142.122.90', '185.220.101.9']
      });
    }
  };

  const filteredFeeds = RECENT_THREAT_FEEDS.filter(item => {
    const matchesSearch = 
      item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.variant.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.summary.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = selectedSeverity === 'ALL' || item.severity === selectedSeverity;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6 pb-12" id="cybershield-threat-intel-view">
      {/* Header */}
      <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D]">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h1 className="text-xl font-semibold text-[#F8FAFC]">
              Threat Intelligence
            </h1>
            <p className="text-xs text-[#94A3B8] mt-0.5">
              Live database of global ransomware campaigns, IOC signatures, and zero-day vulnerabilities.
            </p>
          </div>
          <div className="text-xs text-[#94A3B8] font-mono">
            Feed: Connected
          </div>
        </div>
      </div>

      {/* IOC Hash & Keyword Fast Lookup Tool */}
      <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3.5">
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
            IOC &amp; Hash Reputation Query
          </h2>
          <p className="text-xs text-[#94A3B8] mt-0.5">Lookup any MD5, SHA-256, CVE identifier, or C2 IP address across threat intelligence feeds</p>
        </div>

        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row gap-2.5">
          <div className="flex-1 relative">
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Enter SHA-256, MD5, CVE-2026-XXXX, or strain name..."
              className="w-full bg-[#0B1220] border border-[#24344D] focus:border-[#3B82F6] rounded-lg px-3.5 py-2 text-xs font-mono text-[#F8FAFC] outline-none placeholder-[#94A3B8]/60"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-xs transition flex items-center justify-center gap-1.5"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Search IOC</span>
          </button>
        </form>

        {lookupResult && (
          <div className="p-4 rounded-lg bg-[#0B1220] border border-[#24344D] text-xs font-mono space-y-2.5">
            <div className="flex items-center justify-between pb-2 border-b border-[#24344D]">
              <span className="text-[#3B82F6] font-medium flex items-center gap-1.5">
                <Check className="w-3.5 h-3.5 text-[#22C55E]" /> Match Identified
              </span>
              <span className="text-[11px] text-[#94A3B8]">First Seen: {lookupResult.firstSeen}</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Strain</span>
                <div className="text-[#F8FAFC] font-medium mt-0.5">{lookupResult.family}</div>
              </div>
              <div>
                <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Verdict</span>
                <div className="text-[#EF4444] font-medium mt-0.5">{lookupResult.verdict}</div>
              </div>
              <div>
                <span className="text-[#94A3B8] text-[10px] uppercase font-sans">CVE Reference</span>
                <div className="text-[#F59E0B] font-medium mt-0.5">{lookupResult.cve}</div>
              </div>
            </div>

            <div className="pt-2 text-[11px] text-[#94A3B8] border-t border-[#24344D]">
              Associated IPs: <span className="text-[#F8FAFC]">{lookupResult.ips?.join(', ')}</span>
            </div>
          </div>
        )}
      </div>

      {/* Threat Feeds List */}
      <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#24344D]">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-[#EF4444]" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
              Active Threat Advisories ({filteredFeeds.length})
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-[#94A3B8]" />
            <select
              aria-label="Filter threat severity"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-[#16243A] border border-[#24344D] text-[#F8FAFC] text-xs rounded-lg px-2.5 py-1.5 outline-none cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
            </select>
          </div>
        </div>

        <div className="space-y-3">
          {filteredFeeds.map((feed) => (
            <div
              key={feed.id}
              className="p-4 rounded-lg bg-[#0B1220] border border-[#24344D] hover:border-[#3B82F6]/50 transition space-y-2 text-xs"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                    feed.severity === 'CRITICAL' ? 'bg-[#EF4444]/15 text-[#EF4444]' :
                    feed.severity === 'HIGH' ? 'bg-[#F59E0B]/15 text-[#F59E0B]' :
                    'bg-[#94A3B8]/15 text-[#94A3B8]'
                  }`}>
                    {feed.severity}
                  </span>
                  <span className="font-medium text-[#F8FAFC] text-sm">{feed.title}</span>
                </div>
                <span className="text-[11px] text-[#94A3B8] font-mono whitespace-nowrap">{feed.date}</span>
              </div>

              <p className="text-[#94A3B8] text-xs leading-relaxed">
                {feed.summary}
              </p>

              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#24344D] text-[11px]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[#3B82F6]">Targets: {feed.targetIndustries.join(', ')}</span>
                  {feed.cve && (
                    <span className="px-1.5 py-0.2 rounded bg-[#16243A] text-[#F59E0B] border border-[#24344D] text-[10px] font-mono">
                      {feed.cve}
                    </span>
                  )}
                </div>
                <span className="text-[#94A3B8] font-mono">{feed.indicatorCount} Indicators</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

