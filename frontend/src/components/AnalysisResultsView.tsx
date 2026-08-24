import React, { useState } from 'react';
import { SampleAnalysis } from '../types';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Unlock, 
  Lock, 
  FileCode, 
  Activity, 
  Binary, 
  Cpu, 
  FileText, 
  Key, 
  Radio, 
  Copy, 
  Check, 
  Layers, 
  Zap,
  Terminal
} from 'lucide-react';

interface AnalysisResultsViewProps {
  sample: SampleAnalysis;
  allSamples: SampleAnalysis[];
  onSelectSample: (sample: SampleAnalysis) => void;
  onOpenDecryptor: (sample: SampleAnalysis) => void;
  onViewReport: (sample: SampleAnalysis) => void;
  onNavigate: (tab: string) => void;
}

export const AnalysisResultsView: React.FC<AnalysisResultsViewProps> = ({
  sample,
  allSamples,
  onSelectSample,
  onOpenDecryptor,
  onViewReport,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'static' | 'dynamic' | 'crypto' | 'ml' | 'mitre' | 'iocs'>('overview');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const isMalicious = sample.verdict === 'MALICIOUS';
  const isSafe = sample.verdict === 'SAFE';

  return (
    <div className="space-y-6 pb-12" id="cybershield-analysis-results-view">
      {/* Header & Sample Switcher */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 p-5 rounded-xl bg-[#111C2E] border border-[#24344D]">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-[#94A3B8] uppercase">Sample {sample.id}</span>
          </div>
          <h1 className="text-xl font-semibold text-[#F8FAFC]">
            {sample.fileName}
          </h1>
          <p className="text-xs text-[#94A3B8]">
            Format: {sample.fileType} • Size: {sample.fileSize} • Ingested: {sample.timestamp}
          </p>
        </div>

        {/* Right Switcher & Report Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Select sample"
            value={sample.id}
            onChange={(e) => {
              const found = allSamples.find(s => s.id === e.target.value);
              if (found) onSelectSample(found);
            }}
            className="bg-[#16243A] border border-[#24344D] text-[#F8FAFC] text-xs rounded-lg px-3 py-2 focus:border-[#3B82F6] outline-none cursor-pointer"
          >
            {allSamples.map((s) => (
              <option key={s.id} value={s.id}>
                {s.fileName} ({s.verdict})
              </option>
            ))}
          </select>

          {sample.decryptionStatus === 'DECRYPTABLE' && (
            <button
              id="results-launch-decryptor-btn"
              onClick={() => onOpenDecryptor(sample)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-xs transition"
            >
              <Key className="w-3.5 h-3.5" />
              <span>Decrypt</span>
            </button>
          )}

          <button
            id="results-view-report-btn"
            onClick={() => onViewReport(sample)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#16243A] hover:bg-[#24344D] border border-[#24344D] text-[#F8FAFC] font-medium text-xs transition"
          >
            <FileText className="w-3.5 h-3.5 text-[#3B82F6]" />
            <span>Report</span>
          </button>
        </div>
      </div>

      {/* Primary Key Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* Verdict */}
        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <span className="text-[11px] text-[#94A3B8] uppercase font-medium">Verdict</span>
          <div className="flex items-center gap-1.5 pt-0.5">
            {isMalicious ? <ShieldAlert className="w-4 h-4 text-[#EF4444]" /> : isSafe ? <ShieldCheck className="w-4 h-4 text-[#22C55E]" /> : <AlertTriangle className="w-4 h-4 text-[#F59E0B]" />}
            <span className={`text-base font-bold ${isMalicious ? 'text-[#EF4444]' : isSafe ? 'text-[#22C55E]' : 'text-[#F59E0B]'}`}>
              {sample.verdict}
            </span>
          </div>
          <span className="text-[11px] text-[#94A3B8] block truncate">
            {isMalicious ? 'Malware confirmed' : isSafe ? 'Verified clean' : 'Suspicious'}
          </span>
        </div>

        {/* Threat Level */}
        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <span className="text-[11px] text-[#94A3B8] uppercase font-medium">Threat Level</span>
          <span className={`text-base font-bold block pt-0.5 ${
            sample.threatLevel === 'CRITICAL' ? 'text-[#EF4444]' : sample.threatLevel === 'HIGH' ? 'text-[#F59E0B]' : sample.threatLevel === 'SAFE' ? 'text-[#22C55E]' : 'text-[#94A3B8]'
          }`}>
            {sample.threatLevel}
          </span>
          <span className="text-[11px] text-[#94A3B8] block">Entropy: {sample.entropy} / 8.0</span>
        </div>

        {/* Confidence Score */}
        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <span className="text-[11px] text-[#94A3B8] uppercase font-medium">ML Confidence</span>
          <div className="text-base font-bold text-[#3B82F6] pt-0.5">{sample.confidenceScore}%</div>
          <div className="w-full bg-[#16243A] h-1.5 rounded-full overflow-hidden mt-1">
            <div className="bg-[#3B82F6] h-full" style={{ width: `${sample.confidenceScore}%` }} />
          </div>
        </div>

        {/* Ransomware Family */}
        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <span className="text-[11px] text-[#94A3B8] uppercase font-medium">Strain / Family</span>
          <span className="text-base font-bold text-[#F8FAFC] block truncate pt-0.5">
            {sample.ransomwareFamily}
          </span>
          <span className="text-[11px] text-[#94A3B8] block">DeepMalwareNet</span>
        </div>

        {/* Decryption Status */}
        <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-1">
          <span className="text-[11px] text-[#94A3B8] uppercase font-medium">Decryption</span>
          <div className="flex items-center gap-1.5 pt-0.5">
            {sample.decryptionStatus === 'DECRYPTABLE' ? (
              <span className="text-base font-bold text-[#22C55E] flex items-center gap-1">
                <Unlock className="w-4 h-4" /> Feasible
              </span>
            ) : sample.decryptionStatus === 'UNSUPPORTED' ? (
              <span className="text-base font-bold text-[#94A3B8] flex items-center gap-1">
                <Lock className="w-4 h-4" /> Unknown
              </span>
            ) : (
              <span className="text-base font-bold text-[#22C55E]">Clean</span>
            )}
          </div>
          <span className="text-[11px] text-[#94A3B8] block">
            {sample.decryptionSuccessRate ? `${sample.decryptionSuccessRate}% rate` : 'N/A'}
          </span>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex flex-wrap gap-1.5 border-b border-[#24344D] pb-2">
        {[
          { id: 'overview', label: 'Overview', icon: Activity },
          { id: 'static', label: 'Static Analysis', icon: Binary },
          { id: 'dynamic', label: 'Sandbox Dynamic', icon: Cpu },
          { id: 'crypto', label: 'Crypto & Keys', icon: Key },
          { id: 'ml', label: 'ML Ensemble', icon: Zap },
          { id: 'mitre', label: 'MITRE ATT&CK', icon: Layers },
          { id: 'iocs', label: 'IOCs & YARA', icon: FileCode }
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                isActive
                  ? 'bg-[#16243A] text-[#F8FAFC] border border-[#24344D]'
                  : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#111C2E]'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-[#3B82F6]' : 'text-[#94A3B8]'}`} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Overview */}
      {activeSubTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-8 space-y-5">
            {/* Summary */}
            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-2.5">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Executive Threat Summary
              </h2>
              <p className="text-xs text-[#F8FAFC] leading-relaxed">
                {sample.threatSummary}
              </p>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {sample.tags.map((tag) => (
                  <span key={tag} className="px-2 py-0.5 rounded bg-[#16243A] text-[#94A3B8] border border-[#24344D] text-[11px] font-mono">
                    #{tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Hashes & Metadata */}
            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3 font-mono text-xs">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] font-sans">
                Checksums &amp; Cryptographic Hashes
              </h2>
              <div className="space-y-2">
                <div className="p-2.5 rounded-lg bg-[#0B1220] border border-[#24344D] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#94A3B8] text-[10px] block uppercase font-sans">SHA-256</span>
                    <span className="text-[#F8FAFC] text-xs select-all truncate block">{sample.sha256}</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(sample.sha256, 'sha256')}
                    className="p-1.5 rounded hover:bg-[#16243A] text-[#94A3B8] hover:text-[#F8FAFC] transition flex-shrink-0"
                  >
                    {copiedHash === 'sha256' ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5 text-[#94A3B8]" />}
                  </button>
                </div>

                <div className="p-2.5 rounded-lg bg-[#0B1220] border border-[#24344D] flex items-center justify-between">
                  <div className="truncate mr-2">
                    <span className="text-[#94A3B8] text-[10px] block uppercase font-sans">MD5</span>
                    <span className="text-[#F8FAFC] text-xs select-all truncate block">{sample.md5}</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(sample.md5, 'md5')}
                    className="p-1.5 rounded hover:bg-[#16243A] text-[#94A3B8] hover:text-[#F8FAFC] transition flex-shrink-0"
                  >
                    {copiedHash === 'md5' ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5 text-[#94A3B8]" />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Remediation & Decryption Card */}
          <div className="lg:col-span-4 space-y-5">
            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Recovery Feasibility
              </h2>
              <div className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D] text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[#94A3B8]">Feasibility:</span>
                  <span className="text-[#3B82F6] font-medium">{sample.decryptionStatus}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[#94A3B8]">Recovery Rate:</span>
                  <span className="text-[#22C55E] font-medium">{sample.decryptionSuccessRate ? `${sample.decryptionSuccessRate}%` : 'N/A'}</span>
                </div>
                <p className="text-[11px] text-[#94A3B8] pt-1.5 border-t border-[#24344D]">
                  {sample.decryptionMethod}
                </p>
              </div>

              {sample.decryptionStatus === 'DECRYPTABLE' && (
                <button
                  onClick={() => onOpenDecryptor(sample)}
                  className="w-full py-2 px-3 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-xs transition"
                >
                  Launch Decryptor
                </button>
              )}
            </div>

            {/* Remediation */}
            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3 text-xs">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Incident Response Actions
              </h2>
              <ul className="space-y-2 text-[#94A3B8]">
                {sample.remediation.map((step, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="w-4 h-4 rounded bg-[#16243A] text-[#3B82F6] border border-[#24344D] flex items-center justify-center text-[10px] font-mono flex-shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span className="text-xs text-[#F8FAFC]">{step}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Static */}
      {activeSubTab === 'static' && (
        <div className="space-y-5">
          <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3.5">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                PE Sections &amp; Shannon Entropy
              </h2>
              <span className="text-xs text-[#94A3B8] font-mono">
                Compiler: {sample.staticAnalysis.compiler}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-[#24344D] text-[#94A3B8] text-[11px] uppercase bg-[#16243A]">
                    <th className="py-2.5 px-3 font-medium">Section</th>
                    <th className="py-2.5 px-3 font-medium">Virtual Size</th>
                    <th className="py-2.5 px-3 font-medium">Raw Size</th>
                    <th className="py-2.5 px-3 font-medium">Entropy</th>
                    <th className="py-2.5 px-3 font-medium">Characteristics</th>
                    <th className="py-2.5 px-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#24344D]/60">
                  {sample.staticAnalysis.sections.map((sec, i) => (
                    <tr key={i} className="hover:bg-[#16243A]">
                      <td className="py-2.5 px-3 font-medium text-[#F8FAFC]">{sec.name}</td>
                      <td className="py-2.5 px-3 text-[#94A3B8]">{sec.virtualSize}</td>
                      <td className="py-2.5 px-3 text-[#94A3B8]">{sec.rawSize}</td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <div className="w-14 bg-[#16243A] h-1.5 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${sec.entropy > 7.5 ? 'bg-[#EF4444]' : sec.entropy > 6.0 ? 'bg-[#F59E0B]' : 'bg-[#22C55E]'}`}
                              style={{ width: `${(sec.entropy / 8) * 100}%` }}
                            />
                          </div>
                          <span className={sec.entropy > 7.5 ? 'text-[#EF4444]' : 'text-[#94A3B8]'}>
                            {sec.entropy.toFixed(2)}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-[#94A3B8] text-[11px]">{sec.characteristics}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                          sec.status === 'SUSPICIOUS' ? 'bg-[#EF4444]/15 text-[#EF4444]' :
                          sec.status === 'ANOMALOUS' ? 'bg-[#F59E0B]/15 text-[#F59E0B]' :
                          'text-[#94A3B8]'
                        }`}>
                          {sec.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Suspicious Extracted Strings
              </h2>
              <div className="space-y-1.5 max-h-56 overflow-y-auto font-mono text-xs">
                {sample.staticAnalysis.suspiciousStrings.length === 0 ? (
                  <div className="text-[#94A3B8]/60 italic">No suspicious strings identified.</div>
                ) : (
                  sample.staticAnalysis.suspiciousStrings.map((str, idx) => (
                    <div key={idx} className="p-2 rounded bg-[#0B1220] border border-[#24344D] text-[#EF4444] select-all">
                      {str}
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Imported APIs &amp; Libraries
              </h2>
              <div className="space-y-2 max-h-56 overflow-y-auto font-mono text-xs">
                {sample.staticAnalysis.importedDlls.map((dll, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-[#0B1220] border border-[#24344D] space-y-1">
                    <span className="text-[#3B82F6] font-medium">{dll.dll}</span>
                    <div className="flex flex-wrap gap-1">
                      {dll.functions.map((fn, fIdx) => (
                        <span key={fIdx} className="px-1.5 py-0.5 rounded bg-[#16243A] text-[#94A3B8] text-[10px]">
                          {fn}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Dynamic */}
      {activeSubTab === 'dynamic' && (
        <div className="space-y-5">
          <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
              Execution Process Tree ({sample.dynamicAnalysis.sandboxOS})
            </h2>

            <div className="space-y-2 font-mono text-xs">
              {sample.dynamicAnalysis.processTree.map((p, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D] flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <span className="px-1.5 py-0.5 rounded bg-[#16243A] text-[#3B82F6] text-[10px]">
                      PID: {p.pid}
                    </span>
                    <div>
                      <div className="font-medium text-[#F8FAFC]">{p.name}</div>
                      <div className="text-[#94A3B8] text-[11px] mt-0.5">{p.action}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-right">
                    <span className="text-[10px] text-[#94A3B8]">{p.timestamp}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                      p.status === 'MALICIOUS' ? 'bg-[#EF4444]/15 text-[#EF4444]' :
                      p.status === 'WARNING' ? 'bg-[#F59E0B]/15 text-[#F59E0B]' :
                      'text-[#94A3B8]'
                    }`}>
                      {p.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                C2 Network Telemetry
              </h2>
              <div className="space-y-2 font-mono text-xs">
                {sample.dynamicAnalysis.networkBeacons.length === 0 ? (
                  <div className="text-[#94A3B8]/60 italic">No external network beacons detected.</div>
                ) : (
                  sample.dynamicAnalysis.networkBeacons.map((b, i) => (
                    <div key={i} className="p-2.5 rounded bg-[#0B1220] border border-[#24344D] text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[#EF4444] font-medium">{b.ip}:{b.port}</span>
                        <span className="text-[10px] text-[#94A3B8]">{b.country} • {b.protocol}</span>
                      </div>
                      <div className="text-[#F8FAFC] text-[11px]">{b.domain}</div>
                      <div className="text-[#3B82F6] text-[10px]">{b.action}</div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Extracted Extortion Note
              </h2>
              {sample.dynamicAnalysis.ransomNoteFound ? (
                <div className="p-3 rounded-lg bg-[#0B1220] border border-[#EF4444]/30 font-mono text-xs text-[#F8FAFC] whitespace-pre-wrap max-h-48 overflow-y-auto">
                  {sample.dynamicAnalysis.ransomNoteContent}
                </div>
              ) : (
                <div className="text-[#94A3B8]/60 text-xs font-mono italic">
                  No ransom notes dropped.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Crypto */}
      {activeSubTab === 'crypto' && (
        <div className="space-y-5">
          <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Cryptographic Analysis &amp; Key Derivation
              </h2>
              <span className="px-2 py-0.5 rounded bg-[#16243A] text-[#3B82F6] border border-[#24344D] text-xs font-mono">
                {sample.cryptoAnalysis.encryptionAlgorithm}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D]">
                <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Key Size / Mode</span>
                <div className="text-[#F8FAFC] font-medium mt-0.5">{sample.cryptoAnalysis.keySize}</div>
                <div className="text-[#3B82F6] text-[11px] mt-0.5">{sample.cryptoAnalysis.mode}</div>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D]">
                <span className="text-[#94A3B8] text-[10px] uppercase font-sans">PRNG / IV Flaw</span>
                <div className={`font-medium mt-0.5 ${sample.cryptoAnalysis.prngFlawDetected ? 'text-[#22C55E]' : 'text-[#94A3B8]'}`}>
                  {sample.cryptoAnalysis.prngFlawDetected ? 'Vulnerability Found' : 'Secure Implementation'}
                </div>
                <div className="text-[#94A3B8] text-[11px] mt-0.5">
                  {sample.cryptoAnalysis.prngFlawDetected ? 'Reconstruction possible' : 'No weak seed'}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D]">
                <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Throughput</span>
                <div className="text-[#F8FAFC] font-medium mt-0.5">{sample.cryptoAnalysis.encryptionSpeed}</div>
                <div className="text-[#94A3B8] text-[11px] mt-0.5">Multi-threaded</div>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0B1220] border border-[#24344D] space-y-1.5">
              <h3 className="text-xs font-medium text-[#F8FAFC]">
                Cryptographic Flaw Assessment
              </h3>
              <p className="text-xs text-[#94A3B8] leading-relaxed font-sans">
                {sample.cryptoAnalysis.flawDescription}
              </p>
            </div>

            {sample.decryptionKeyCandidate && (
              <div className="p-4 rounded-lg bg-[#16243A] border border-[#24344D] space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-[#F8FAFC]">
                    Derived Candidate Key
                  </span>
                  <span className="text-[10px] text-[#22C55E] font-medium font-mono">READY</span>
                </div>
                <div className="p-2.5 rounded bg-[#0B1220] border border-[#24344D] font-mono text-xs text-[#3B82F6] select-all flex items-center justify-between">
                  <span className="truncate mr-2">{sample.decryptionKeyCandidate}</span>
                  <button
                    onClick={() => copyToClipboard(sample.decryptionKeyCandidate!, 'key')}
                    className="p-1 rounded hover:bg-[#16243A] text-[#94A3B8] hover:text-[#F8FAFC]"
                  >
                    {copiedHash === 'key' ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <button
                  onClick={() => onOpenDecryptor(sample)}
                  className="w-full py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-xs transition"
                >
                  Test in Decryption Workbench
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 5: ML */}
      {activeSubTab === 'ml' && (
        <div className="space-y-5">
          <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Ensemble Model Classification
              </h2>
              <span className="text-xs font-mono text-[#3B82F6]">
                {sample.mlClassification.modelName}
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              {sample.mlClassification.familyProbabilities.map((fp, i) => (
                <div key={i} className="space-y-1">
                  <div className="flex items-center justify-between text-[#F8FAFC]">
                    <span>{fp.family}</span>
                    <span className="text-[#3B82F6]">{fp.probability}%</span>
                  </div>
                  <div className="w-full bg-[#16243A] h-1.5 rounded-full overflow-hidden">
                    <div 
                      className={`h-full ${i === 0 ? 'bg-[#3B82F6]' : 'bg-[#24344D]'}`} 
                      style={{ width: `${fp.probability}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-[#24344D] space-y-2.5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Top Predictive Features
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {sample.mlClassification.topFeatures.map((tf, i) => (
                  <div key={i} className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D] text-xs font-mono space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[#F8FAFC] font-medium truncate">{tf.feature}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded ${
                        tf.influence === 'Malicious' ? 'bg-[#EF4444]/15 text-[#EF4444]' : 'bg-[#22C55E]/15 text-[#22C55E]'
                      }`}>
                        {tf.influence}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#94A3B8] font-sans">{tf.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 6: MITRE */}
      {activeSubTab === 'mitre' && (
        <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
            MITRE ATT&amp;CK Matrix Mapping
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
            {sample.mitreTactics.map((t) => (
              <div key={t.id} className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D] space-y-1.5 font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-[#3B82F6] font-medium">{t.id}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#16243A] text-[#94A3B8]">
                    {t.phase}
                  </span>
                </div>
                <div className="font-medium text-[#F8FAFC] font-sans">{t.name}</div>
                <div className="text-[#EF4444] text-[11px]">{t.technique}</div>
                <p className="text-[#94A3B8] text-[11px] font-sans">{t.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 7: IOCs */}
      {activeSubTab === 'iocs' && (
        <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
              YARA Detection Rule
            </h2>
            <button
              onClick={() => copyToClipboard(sample.iocs.yaraRuleText, 'yara')}
              className="flex items-center gap-1 text-xs text-[#3B82F6] hover:underline font-mono"
            >
              {copiedHash === 'yara' ? <Check className="w-3.5 h-3.5 text-[#22C55E]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy YARA</span>
            </button>
          </div>

          <pre className="p-3.5 rounded-lg bg-[#0B1220] border border-[#24344D] text-[#94A3B8] text-xs font-mono overflow-x-auto whitespace-pre">
            {sample.iocs.yaraRuleText}
          </pre>
        </div>
      )}
    </div>
  );
};

