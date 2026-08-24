import React from 'react';
import { SampleAnalysis } from '../types';
import { CyberLogo } from './CyberLogo';
import { 
  Printer, 
  Download, 
  ArrowLeft
} from 'lucide-react';

interface ReportViewProps {
  sample: SampleAnalysis;
  onBack: () => void;
}

export const ReportView: React.FC<ReportViewProps> = ({ sample, onBack }) => {
  const handlePrint = () => {
    window.print();
  };

  const handleExportJSON = () => {
    const reportData = {
      platform: 'CyberShield Ransomware Analysis & Decryption Platform',
      reportGenerated: new Date().toISOString(),
      sampleMetadata: {
        id: sample.id,
        fileName: sample.fileName,
        fileSize: sample.fileSize,
        md5: sample.md5,
        sha256: sample.sha256,
        entropy: sample.entropy,
        verdict: sample.verdict,
        threatLevel: sample.threatLevel,
        confidenceScore: sample.confidenceScore,
        ransomwareFamily: sample.ransomwareFamily,
      },
      cryptoAnalysis: sample.cryptoAnalysis,
      decryptionStatus: sample.decryptionStatus,
      mitreTactics: sample.mitreTactics,
      iocs: sample.iocs,
      remediation: sample.remediation
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberShield_Report_${sample.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const isMalicious = sample.verdict === 'MALICIOUS';

  return (
    <div className="space-y-6 max-w-4xl mx-auto pb-16" id="cybershield-report-page">
      {/* Top Action Bar (hidden when printed) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-[#111C2E] border border-[#24344D] print:hidden">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-xs text-[#94A3B8] hover:text-[#F8FAFC] transition font-medium"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Analysis</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJSON}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#16243A] hover:bg-[#24344D] border border-[#24344D] text-[#F8FAFC] text-xs font-medium transition"
          >
            <Download className="w-3.5 h-3.5 text-[#3B82F6]" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-xs transition"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {/* Main Printable Document Card */}
      <div className="p-6 sm:p-10 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-6 print:bg-white print:text-black print:p-4 print:border-none print:shadow-none">
        {/* Report Header & Branding */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-[#24344D] print:border-slate-300">
          <div>
            <CyberLogo size="md" showSubtitle={true} glow={false} />
            <h1 className="text-lg sm:text-xl font-semibold text-[#F8FAFC] print:text-black mt-2">
              Forensic Analysis Report
            </h1>
            <p className="text-xs font-mono text-[#94A3B8] print:text-slate-600 mt-0.5">
              Ref: CSR-{sample.id} • Classification: TLP:AMBER • Date: {new Date().toLocaleDateString()}
            </p>
          </div>

          <div className="text-left sm:text-right font-mono text-xs space-y-0.5">
            <div className="text-[#94A3B8] print:text-slate-600">CyberShield SOC Core</div>
            <div className="text-[#3B82F6] print:text-blue-600 font-medium">DeepMalwareNet v4.8</div>
            <div className="text-[#94A3B8]/60 text-[10px]">NIST CSF Aligned</div>
          </div>
        </div>

        {/* 1. Sample Information */}
        <div className="space-y-2.5">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] print:text-slate-700">
            1. Sample Identifiers
          </h2>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
            <div className="p-3 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300">
              <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Filename</span>
              <div className="font-medium text-[#F8FAFC] print:text-black truncate mt-0.5">{sample.fileName}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300">
              <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Size &amp; Type</span>
              <div className="font-medium text-[#F8FAFC] print:text-black mt-0.5">{sample.fileSize} ({sample.fileType.split(' ')[0]})</div>
            </div>
            <div className="p-3 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300">
              <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Analyzed</span>
              <div className="font-medium text-[#F8FAFC] print:text-black mt-0.5">{sample.analyzedAt}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300">
              <span className="text-[#94A3B8] text-[10px] uppercase font-sans">Shannon Entropy</span>
              <div className={`font-medium mt-0.5 ${sample.entropy > 7.5 ? 'text-[#EF4444] print:text-red-600' : 'text-[#F8FAFC] print:text-black'}`}>
                {sample.entropy} / 8.0
              </div>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300 font-mono text-xs space-y-1">
            <div className="text-[#94A3B8] print:text-slate-700">SHA-256: <span className="text-[#F8FAFC] print:text-black">{sample.sha256}</span></div>
            <div className="text-[#94A3B8] print:text-slate-700">MD5: <span className="text-[#F8FAFC] print:text-black">{sample.md5}</span></div>
          </div>
        </div>

        {/* 2. Threat Summary & Verdict */}
        <div className="space-y-2.5">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] print:text-slate-700">
            2. Classification &amp; Summary
          </h2>

          <div className="p-4 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300 space-y-2.5">
            <div className="flex flex-wrap items-center gap-3">
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                isMalicious ? 'bg-[#EF4444]/15 text-[#EF4444] print:text-red-800' : 'bg-[#22C55E]/15 text-[#22C55E]'
              }`}>
                {sample.verdict}
              </span>
              <span className="text-xs font-mono text-[#F8FAFC] print:text-slate-800">
                Threat Level: {sample.threatLevel} ({sample.confidenceScore}% Confidence)
              </span>
              <span className="text-xs font-mono text-[#3B82F6] print:text-blue-700">
                Family: {sample.ransomwareFamily}
              </span>
            </div>

            <p className="text-xs text-[#94A3B8] print:text-slate-800 leading-relaxed font-sans">
              {sample.threatSummary}
            </p>
          </div>
        </div>

        {/* 3. Static & Dynamic Highlights */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300 space-y-2 text-xs font-mono">
            <h3 className="font-semibold text-[#F8FAFC] print:text-blue-700 uppercase">
              3. Static Analysis
            </h3>
            <ul className="space-y-1 text-[#94A3B8] print:text-slate-800">
              <li>• Architecture: {sample.staticAnalysis.architecture} ({sample.staticAnalysis.subsystem})</li>
              <li>• Compiler: {sample.staticAnalysis.compiler}</li>
              <li>• Packing: {sample.staticAnalysis.isPacked ? `Yes (${sample.staticAnalysis.packerName})` : 'None'}</li>
              <li>• Anti-Debug: {sample.staticAnalysis.antiDebugDetected ? 'Detected' : 'None'}</li>
            </ul>
          </div>

          <div className="p-4 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300 space-y-2 text-xs font-mono">
            <h3 className="font-semibold text-[#F8FAFC] print:text-blue-700 uppercase">
              4. Sandbox Execution
            </h3>
            <ul className="space-y-1 text-[#94A3B8] print:text-slate-800">
              <li>• Environment: {sample.dynamicAnalysis.sandboxOS}</li>
              <li>• Shadow Copies: {sample.dynamicAnalysis.shadowCopiesDeleted ? 'Deleted (vssadmin)' : 'Untouched'}</li>
              <li>• Ransom Note: {sample.dynamicAnalysis.ransomNoteFound ? 'Extracted' : 'None'}</li>
              <li>• Network Beacons: {sample.dynamicAnalysis.networkBeacons.length} endpoints</li>
            </ul>
          </div>
        </div>

        {/* 5. Crypto Analysis & Decryption Result */}
        <div className="space-y-2.5">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] print:text-slate-700">
            5. Cryptographic Feasibility
          </h2>

          <div className="p-4 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] print:text-slate-700">Cipher Algorithm:</span>
              <span className="text-[#F8FAFC] print:text-black font-medium">{sample.cryptoAnalysis.encryptionAlgorithm}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] print:text-slate-700">Decryption Status:</span>
              <span className="text-[#3B82F6] print:text-blue-700 font-medium">{sample.decryptionStatus}</span>
            </div>
            <p className="text-[#94A3B8] print:text-slate-800 text-xs font-sans leading-relaxed pt-1 border-t border-[#24344D] print:border-slate-300">
              {sample.cryptoAnalysis.flawDescription}
            </p>
          </div>
        </div>

        {/* 6. Remediation Roadmap */}
        <div className="space-y-2.5">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8] print:text-slate-700">
            6. Recommended Incident Response
          </h2>

          <div className="p-4 rounded-lg bg-[#0B1220] print:bg-slate-100 border border-[#24344D] print:border-slate-300">
            <ul className="space-y-1.5 text-xs text-[#94A3B8] print:text-slate-800 font-sans">
              {sample.remediation.map((step, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="font-medium text-[#3B82F6] print:text-blue-700">{idx + 1}.</span>
                  <span className="text-[#F8FAFC] print:text-black">{step}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Sign-off Footer */}
        <div className="pt-4 border-t border-[#24344D] print:border-slate-300 flex flex-col sm:flex-row items-center justify-between text-[#94A3B8] print:text-slate-600 text-[11px] font-mono">
          <span>CyberShield Ransomware Defense Framework © 2026</span>
          <span>Lead Analyst Signature: _______________________</span>
        </div>
      </div>
    </div>
  );
};

