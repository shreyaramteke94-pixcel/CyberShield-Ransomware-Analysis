import React, { useState, useEffect } from 'react';
import { SampleAnalysis, SandboxDetectorResponse, SandboxJobResponse, EligibilityResult } from '../types';
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
  Terminal,
  Play,
  RotateCw,
  Info,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ShieldX,
  FlaskConical
} from 'lucide-react';
import { 
  fetchSandboxStatus, 
  submitSandboxJob, 
  fetchSandboxJob, 
  fetchSandboxJobs 
} from '../services/sandboxApi';
import { fetchRecoveryEligibility } from '../services/recoveryApi';

interface AnalysisResultsViewProps {
  sample: SampleAnalysis;
  allSamples: SampleAnalysis[];
  onSelectSample: (sample: SampleAnalysis) => void;
  onOpenDecryptor: (sample: SampleAnalysis) => void;
  onViewReport: (sample: SampleAnalysis) => void;
  onNavigate: (tab: string) => void;
  onUpdateSample?: (sample: SampleAnalysis) => void;
}

export const AnalysisResultsView: React.FC<AnalysisResultsViewProps> = ({
  sample,
  allSamples,
  onSelectSample,
  onOpenDecryptor,
  onViewReport,
  onUpdateSample,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'static' | 'dynamic' | 'crypto' | 'ml' | 'mitre' | 'iocs'>('overview');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Sandbox API State
  const [sandboxStatus, setSandboxStatus] = useState<SandboxDetectorResponse | null>(null);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(false);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [activeJob, setActiveJob] = useState<SandboxJobResponse | null>(sample.sandboxJob || null);
  const [isSubmittingJob, setIsSubmittingJob] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [optInConfirmed, setOptInConfirmed] = useState<boolean>(false);
  const [selectedTimeout, setSelectedTimeout] = useState<number>(60);

  // Recovery Eligibility API State
  const [eligibility, setEligibility] = useState<EligibilityResult | null>(null);
  const [eligibilityLoading, setEligibilityLoading] = useState<boolean>(false);
  const [eligibilityError, setEligibilityError] = useState<string | null>(null);

  // Load sandbox environment status and existing jobs on tab activation or sample change
  useEffect(() => {
    let isMounted = true;
    setActiveJob(sample.sandboxJob || null);
    setSubmitError(null);

    if (activeSubTab === 'dynamic') {
      setLoadingStatus(true);
      setStatusError(null);

      fetchSandboxStatus()
        .then((data) => {
          if (isMounted) {
            setSandboxStatus(data);
            setLoadingStatus(false);
          }
        })
        .catch((err) => {
          if (isMounted) {
            setStatusError(err instanceof Error ? err.message : 'Failed to query sandbox status.');
            setLoadingStatus(false);
          }
        });

      fetchSandboxJobs()
        .then((jobs) => {
          if (isMounted && jobs && jobs.length > 0) {
            const match = jobs.find((j) => j.sample_id === sample.id);
            if (match) {
              setActiveJob(match);
              if (onUpdateSample && !sample.sandboxJob) {
                onUpdateSample({ ...sample, sandboxJob: match });
              }
            }
          }
        })
        .catch(() => {
          // non-critical if jobs list fails
        });
    }

    return () => {
      isMounted = false;
    };
  }, [activeSubTab, sample.id]);

  // Responsible polling when a job is QUEUED or RUNNING; stops on terminal states
  useEffect(() => {
    if (!activeJob) return;
    if (activeJob.status !== 'QUEUED' && activeJob.status !== 'RUNNING') {
      return;
    }

    const intervalId = setInterval(async () => {
      try {
        const updated = await fetchSandboxJob(activeJob.job_id);
        setActiveJob(updated);
        if (onUpdateSample) {
          onUpdateSample({ ...sample, sandboxJob: updated });
        }
      } catch (err) {
        console.error('Failed to poll sandbox job:', err);
      }
    }, 2000);

    return () => clearInterval(intervalId);
  }, [activeJob?.job_id, activeJob?.status]);

  // Check real ransomware recovery eligibility for the current sample
  useEffect(() => {
    let isMounted = true;
    setEligibility(null);
    setEligibilityLoading(true);
    setEligibilityError(null);

    fetchRecoveryEligibility(sample.id)
      .then((data) => {
        if (isMounted) {
          setEligibility(data);
          setEligibilityLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setEligibilityError(err instanceof Error ? err.message : 'Eligibility check unavailable.');
          setEligibilityLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [sample.id]);

  const handleSubmitDynamicAnalysis = async () => {
    if (!optInConfirmed) {
      setSubmitError('Explicit authorization checkbox is required before dynamic execution can proceed.');
      return;
    }

    setIsSubmittingJob(true);
    setSubmitError(null);

    try {
      const job = await submitSandboxJob({
        sample_id: sample.id,
        confirm_dynamic_execution: true,
        timeout_seconds: selectedTimeout,
      });

      setActiveJob(job);
      if (onUpdateSample) {
        onUpdateSample({ ...sample, sandboxJob: job });
      }
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Dynamic analysis request failed.');
    } finally {
      setIsSubmittingJob(false);
    }
  };

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

          <button
            id="results-launch-demo-workbench-btn"
            onClick={() => onOpenDecryptor(sample)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#16243A] hover:bg-[#24344D] border border-[#24344D] text-[#CBD5E1] hover:text-[#F8FAFC] font-medium text-xs transition"
            title="Open AES-256-GCM Demonstration Workbench"
          >
            <FlaskConical className="w-3.5 h-3.5 text-[#A855F7]" />
            <span>Demo Workbench</span>
          </button>

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
          <span className="text-[11px] text-[#94A3B8] uppercase font-medium">Decryption Recovery</span>
          <div className="flex items-center gap-1.5 pt-0.5">
            {eligibilityLoading ? (
              <span className="text-base font-bold text-[#94A3B8] flex items-center gap-1">
                <RotateCw className="w-3.5 h-3.5 animate-spin text-[#3B82F6]" /> Checking...
              </span>
            ) : eligibility?.recovery_status === 'READY_FOR_RECOVERY' ? (
              <span className="text-base font-bold text-[#22C55E] flex items-center gap-1">
                <Unlock className="w-4 h-4" /> Feasible
              </span>
            ) : eligibility?.recovery_status === 'FAMILY_UNKNOWN' ? (
              <span className="text-base font-bold text-[#F59E0B] flex items-center gap-1">
                <AlertTriangle className="w-4 h-4" /> Inconclusive
              </span>
            ) : isSafe ? (
              <span className="text-base font-bold text-[#22C55E] flex items-center gap-1">
                <ShieldCheck className="w-4 h-4" /> Clean
              </span>
            ) : (
              <span className="text-base font-bold text-[#94A3B8] flex items-center gap-1">
                <Lock className="w-4 h-4" /> Unavailable
              </span>
            )}
          </div>
          <span className="text-[11px] text-[#94A3B8] block truncate">
            {eligibilityLoading
              ? 'Querying decryptor registry...'
              : eligibility
              ? eligibility.compatible_adapters.length > 0
                ? `${eligibility.compatible_adapters.length} adapter(s) found`
                : 'No decryptor available'
              : isSafe
              ? 'No recovery needed'
              : 'Decryption unavailable'}
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

      {/* Tab 3: Dynamic - Real Sandbox Dynamic Analysis */}
      {activeSubTab === 'dynamic' && (
        <div className="space-y-6">
          {/* Section 1: Environment Readiness & Host Containment Posture */}
          <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                  Container Sandbox Environment Posture
                </h2>
                <p className="text-xs text-[#94A3B8] mt-0.5">
                  Probes host for Docker runtime, daemon reachability, and verified sandbox image.
                </p>
              </div>

              {loadingStatus ? (
                <div className="flex items-center gap-2 text-xs text-[#94A3B8]">
                  <RotateCw className="w-3.5 h-3.5 animate-spin text-[#3B82F6]" />
                  <span>Probing container runtime...</span>
                </div>
              ) : sandboxStatus ? (
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                      sandboxStatus.sandbox_status === 'AVAILABLE'
                        ? 'bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30'
                        : 'bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30'
                    }`}
                  >
                    {sandboxStatus.sandbox_status === 'AVAILABLE' ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5" />
                    )}
                    <span>SANDBOX: {sandboxStatus.sandbox_status}</span>
                  </span>
                </div>
              ) : null}
            </div>

            {statusError && (
              <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-800/60 text-xs text-red-200 flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold text-red-300">Sandbox Service Connection Error</div>
                  <div className="mt-0.5">{statusError}</div>
                  <div className="mt-1 text-[11px] text-red-300/80">
                    Ensure the CyberShield FastAPI backend is running at http://localhost:8000.
                  </div>
                </div>
              </div>
            )}

            {sandboxStatus && (
              <div className="space-y-3 pt-1">
                {sandboxStatus.sandbox_status === 'UNAVAILABLE' ? (
                  <div className="p-4 rounded-lg bg-[#16243A] border border-[#F59E0B]/30 space-y-2.5 text-xs">
                    <div className="flex items-center gap-2 text-[#F59E0B] font-semibold">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>Dynamic Container Detonation Unavailable on This Host</span>
                    </div>

                    <div className="space-y-1 text-[#CBD5E1] pl-6 font-mono text-[11px]">
                      {sandboxStatus.diagnostics.map((diag, i) => (
                        <div key={i} className="flex items-start gap-1.5">
                          <span className="text-[#F59E0B]">•</span>
                          <span>{diag}</span>
                        </div>
                      ))}
                    </div>

                    {sandboxStatus.prerequisites.length > 0 && (
                      <div className="pt-2 border-t border-[#24344D]/60 pl-6 space-y-1">
                        <div className="text-[11px] uppercase tracking-wider text-[#94A3B8] font-semibold">
                          Prerequisites to Enable Dynamic Detonation:
                        </div>
                        {sandboxStatus.prerequisites.map((prereq, i) => (
                          <div key={i} className="text-[#94A3B8] text-[11px] font-mono">
                            → {prereq}
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="p-2.5 rounded bg-[#0B1220] border border-[#24344D] text-[#94A3B8] text-[11px] flex items-start gap-2">
                      <ShieldX className="w-4 h-4 text-[#EF4444] shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-[#F8FAFC]">Host Subprocess Fallback Strictly Prohibited:</strong>{' '}
                        Untrusted binaries are never executed directly on the host machine. Without a verified container sandbox, dynamic execution is safely refused.
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-3.5 rounded-lg bg-[#16243A] border border-[#22C55E]/30 text-xs space-y-1">
                    <div className="flex items-center gap-2 text-[#22C55E] font-semibold">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Isolated Docker Sandbox Environment Ready</span>
                    </div>
                    <div className="text-[#94A3B8] text-[11px] font-mono">
                      Image: {sandboxStatus.sandbox_image}
                    </div>
                  </div>
                )}

                {/* Defensive Security Boundaries Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                  <div className="p-2.5 rounded bg-[#0B1220] border border-[#24344D]">
                    <div className="text-[#94A3B8] text-[10px] uppercase font-sans">Network Boundary</div>
                    <div className="text-[#22C55E] font-medium mt-0.5">--network none</div>
                    <div className="text-[#94A3B8] text-[10px] mt-0.5">Air-gapped (Zero C2)</div>
                  </div>
                  <div className="p-2.5 rounded bg-[#0B1220] border border-[#24344D]">
                    <div className="text-[#94A3B8] text-[10px] uppercase font-sans">Execution Identity</div>
                    <div className="text-[#3B82F6] font-medium mt-0.5">--user 1000:1000</div>
                    <div className="text-[#94A3B8] text-[10px] mt-0.5">Unprivileged non-root</div>
                  </div>
                  <div className="p-2.5 rounded bg-[#0B1220] border border-[#24344D]">
                    <div className="text-[#94A3B8] text-[10px] uppercase font-sans">Storage Isolation</div>
                    <div className="text-[#F59E0B] font-medium mt-0.5">--read-only rootfs</div>
                    <div className="text-[#94A3B8] text-[10px] mt-0.5">Sample mount :ro</div>
                  </div>
                  <div className="p-2.5 rounded bg-[#0B1220] border border-[#24344D]">
                    <div className="text-[#94A3B8] text-[10px] uppercase font-sans">Resource Envelope</div>
                    <div className="text-[#A855F7] font-medium mt-0.5">1.0 CPU / 512MB</div>
                    <div className="text-[#94A3B8] text-[10px] mt-0.5">64 PIDs / --rm cleanup</div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Section 2: Explicit Opt-in Dynamic Detonation Trigger */}
          <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Dynamic Detonation Authorization
              </h2>
              <span className="text-[11px] font-mono text-[#94A3B8]">
                Target: {sample.id}
              </span>
            </div>

            {/* Operational Warning Alert */}
            <div className="p-3.5 rounded-lg bg-[#0B1220] border border-[#EF4444]/40 text-xs space-y-1.5">
              <div className="flex items-center gap-2 text-[#EF4444] font-semibold">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>Operational Security Notice</span>
              </div>
              <p className="text-[#CBD5E1] text-[11px] leading-relaxed">
                Dynamic detonation triggers actual binary execution within the container sandbox to record runtime behavior (process spawning, extortion notes, encryption speed). Dynamic execution carries inherent operational risk and is strictly opt-in. Host subprocess execution is prohibited.
              </p>
            </div>

            {submitError && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-800/60 text-xs text-red-200 flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{submitError}</span>
              </div>
            )}

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
              {/* Mandatory Checkbox */}
              <label className="flex items-start gap-2.5 cursor-pointer text-xs select-none">
                <input
                  type="checkbox"
                  checked={optInConfirmed}
                  onChange={(e) => setOptInConfirmed(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-[#24344D] bg-[#16243A] text-[#3B82F6] focus:ring-[#3B82F6] focus:ring-offset-0 cursor-pointer"
                />
                <span className="text-[#F8FAFC]">
                  I confirm authorization to detonate sample <span className="font-mono text-[#3B82F6]">{sample.fileName}</span> within the isolated sandbox container.
                </span>
              </label>

              {/* Timeout & Trigger Button */}
              <div className="flex items-center gap-3 shrink-0">
                <div className="flex items-center gap-1.5 text-xs text-[#94A3B8]">
                  <Clock className="w-3.5 h-3.5" />
                  <select
                    value={selectedTimeout}
                    onChange={(e) => setSelectedTimeout(Number(e.target.value))}
                    className="bg-[#16243A] border border-[#24344D] text-[#F8FAFC] text-xs rounded-lg px-2.5 py-1.5 outline-none cursor-pointer"
                  >
                    <option value={30}>30s Timeout</option>
                    <option value={60}>60s (Default)</option>
                    <option value={120}>120s Extended</option>
                  </select>
                </div>

                <button
                  id="btn-detonate-sample"
                  onClick={handleSubmitDynamicAnalysis}
                  disabled={!optInConfirmed || isSubmittingJob || activeJob?.status === 'RUNNING'}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
                    !optInConfirmed || isSubmittingJob || activeJob?.status === 'RUNNING'
                      ? 'bg-[#16243A] text-[#94A3B8]/60 border border-[#24344D] cursor-not-allowed'
                      : 'bg-[#EF4444] hover:bg-red-600 text-white shadow-lg shadow-red-900/20 cursor-pointer'
                  }`}
                >
                  {isSubmittingJob ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Submitting...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Detonate Sample in Sandbox</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Section 3: Live Job Telemetry & Execution Lifecycle */}
          {activeJob ? (
            <div className="space-y-5">
              {/* Job Metadata & State Banner */}
              <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#24344D] pb-3">
                  <div className="space-y-0.5">
                    <div className="text-[11px] font-mono text-[#94A3B8] uppercase">
                      Sandbox Job: {activeJob.job_id}
                    </div>
                    <div className="text-xs font-semibold text-[#F8FAFC]">
                      Sample: {activeJob.filename} ({activeJob.sample_id})
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {activeJob.status === 'RUNNING' && (
                      <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#A855F7]/15 text-[#A855F7] border border-[#A855F7]/30">
                        <RotateCw className="w-3.5 h-3.5 animate-spin" />
                        <span>RUNNING (Polling 2s)</span>
                      </span>
                    )}
                    {activeJob.status === 'COMPLETED' && (
                      <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>COMPLETED</span>
                      </span>
                    )}
                    {activeJob.status === 'UNAVAILABLE' && (
                      <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>UNAVAILABLE</span>
                      </span>
                    )}
                    {activeJob.status === 'TIMED_OUT' && (
                      <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30">
                        <Clock className="w-3.5 h-3.5" />
                        <span>TIMED_OUT</span>
                      </span>
                    )}
                    {activeJob.status === 'FAILED' && (
                      <span className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30">
                        <XCircle className="w-3.5 h-3.5" />
                        <span>FAILED</span>
                      </span>
                    )}
                  </div>
                </div>

                <div className="text-xs text-[#CBD5E1] font-mono leading-relaxed">
                  {activeJob.execution_summary}
                </div>

                {activeJob.error_message && (
                  <div className="p-3 rounded-lg bg-[#0B1220] border border-[#F59E0B]/40 text-xs space-y-1 font-mono text-[#F59E0B]">
                    <div>{activeJob.error_message}</div>
                    {activeJob.security_verifications?.host_execution_prevented && (
                      <div className="text-[11px] text-[#22C55E] pt-1 border-t border-[#24344D]/60">
                        ✓ Safety Assertion: Untrusted binary was NOT executed on the host.
                      </div>
                    )}
                  </div>
                )}

                <div className="flex flex-wrap gap-4 text-[11px] font-mono text-[#94A3B8] pt-1">
                  <div>Submitted: {activeJob.created_at}</div>
                  {activeJob.completed_at && <div>Finished: {activeJob.completed_at}</div>}
                  <div>Operations: {activeJob.operations_run.join(' → ') || 'None'}</div>
                </div>
              </div>

              {/* Observed Telemetry (Only rendered when actually collected; no mock data) */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* Process Tree Observation */}
                <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                      Runtime Process Hierarchy
                    </h2>
                    <span className="text-[11px] font-mono text-[#94A3B8]">
                      Observed: {activeJob.process_tree?.length || 0}
                    </span>
                  </div>

                  {activeJob.process_tree && activeJob.process_tree.length > 0 ? (
                    <div className="space-y-2 font-mono text-xs max-h-60 overflow-y-auto">
                      {activeJob.process_tree.map((p, idx) => (
                        <div key={idx} className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D] flex items-start justify-between gap-3">
                          <div className="flex items-start gap-2">
                            <span className="px-1.5 py-0.5 rounded bg-[#16243A] text-[#3B82F6] text-[10px]">
                              PID: {p.pid}
                            </span>
                            <div>
                              <div className="font-medium text-[#F8FAFC]">{p.name}</div>
                              <div className="text-[#94A3B8] text-[11px] mt-0.5">{p.action}</div>
                            </div>
                          </div>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                            p.status === 'MALICIOUS' ? 'bg-[#EF4444]/15 text-[#EF4444]' : 'text-[#94A3B8]'
                          }`}>
                            {p.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-6 rounded-lg bg-[#0B1220] border border-[#24344D]/60 text-center text-xs text-[#94A3B8]/70 font-mono italic">
                      {activeJob.status === 'RUNNING'
                        ? 'Collecting runtime process tree telemetry...'
                        : 'No child processes observed during sandbox execution.'}
                    </div>
                  )}
                </div>

                {/* Network Beacons Observation */}
                <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                      C2 Network Observations
                    </h2>
                    <span className="text-[11px] font-mono text-[#94A3B8]">
                      Blocked: {activeJob.network_beacons?.length || 0}
                    </span>
                  </div>

                  {activeJob.network_beacons && activeJob.network_beacons.length > 0 ? (
                    <div className="space-y-2 font-mono text-xs max-h-60 overflow-y-auto">
                      {activeJob.network_beacons.map((b, i) => (
                        <div key={i} className="p-2.5 rounded bg-[#0B1220] border border-[#24344D] text-xs space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-[#EF4444] font-medium">{b.ip}:{b.port}</span>
                            <span className="text-[10px] text-[#94A3B8]">{b.protocol}</span>
                          </div>
                          <div className="text-[#F8FAFC] text-[11px]">{b.domain}</div>
                          <div className="text-[#3B82F6] text-[10px]">{b.action}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-6 rounded-lg bg-[#0B1220] border border-[#24344D]/60 text-center text-xs text-[#94A3B8]/70 font-mono italic">
                      Zero outbound network beacons observed. Air-gapped network mode verified (--network none).
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-[#111C2E] border border-[#24344D] text-center space-y-2">
              <Cpu className="w-8 h-8 text-[#94A3B8]/40 mx-auto" />
              <div className="text-xs font-semibold text-[#F8FAFC]">
                No Dynamic Detonation Job Submitted
              </div>
              <p className="text-xs text-[#94A3B8] max-w-md mx-auto">
                Dynamic analysis is strictly opt-in and unexecuted by default. To detonate this sample in the container sandbox, review the security warning above and authorize execution.
              </p>
            </div>
          )}
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
                  Test Candidate Key in Demo Workbench
                </button>
              </div>
            )}
          </div>

          {/* Real Ransomware Recovery Assessment Card */}
          <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#24344D] pb-3">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <Key className="w-4 h-4 text-[#3B82F6]" />
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F8FAFC]">
                    Real Ransomware Recovery Assessment
                  </h3>
                </div>
                <p className="text-[11px] text-[#94A3B8]">
                  Evaluates sample identification against the verified decryptor adapter registry (No More Ransom / Emsisoft).
                </p>
              </div>

              <div>
                {eligibilityLoading ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono bg-[#16243A] text-[#94A3B8] border border-[#24344D]">
                    <RotateCw className="w-3 h-3 animate-spin text-[#3B82F6]" /> Checking Eligibility...
                  </span>
                ) : eligibility?.recovery_status === 'READY_FOR_RECOVERY' ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30">
                    <CheckCircle2 className="w-3.5 h-3.5" /> READY_FOR_RECOVERY
                  </span>
                ) : eligibility?.recovery_status === 'FAMILY_UNKNOWN' ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30">
                    <AlertTriangle className="w-3.5 h-3.5" /> FAMILY_UNKNOWN
                  </span>
                ) : eligibility?.recovery_status === 'DECRYPTOR_UNAVAILABLE' ? (
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30">
                    <Lock className="w-3.5 h-3.5" /> DECRYPTOR_UNAVAILABLE
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono bg-[#16243A] text-[#94A3B8] border border-[#24344D]">
                    <Info className="w-3.5 h-3.5" /> {eligibility?.recovery_status || (isSafe ? 'CLEAN_FILE' : 'UNSUPPORTED')}
                  </span>
                )}
              </div>
            </div>

            {/* Status explanation */}
            <div className="text-xs text-[#CBD5E1] font-mono leading-relaxed bg-[#0B1220] p-3.5 rounded-lg border border-[#24344D]">
              {eligibility?.explanation || (
                isSafe
                  ? 'This sample is verified clean. No ransomware decryption is applicable.'
                  : `Identified strain "${sample.ransomwareFamily}" uses modern authenticated encryption. No verified decryptor adapter is currently available for this family.`
              )}
            </div>

            {/* Evidence & Limitations */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3.5 rounded-lg bg-[#0B1220] border border-[#24344D] space-y-2">
                <span className="text-[11px] font-sans font-semibold uppercase tracking-wider text-[#94A3B8]">
                  Evidence Indicators
                </span>
                <div className="space-y-1.5 text-[11px]">
                  {eligibility?.evidence && eligibility.evidence.length > 0 ? (
                    eligibility.evidence.map((ev, i) => (
                      <div key={i} className="flex items-start gap-1.5 text-[#CBD5E1]">
                        <span className="text-[#3B82F6] shrink-0">•</span>
                        <span>{ev}</span>
                      </div>
                    ))
                  ) : (
                    <>
                      <div className="text-[#CBD5E1]">• Identified Family: {sample.ransomwareFamily}</div>
                      <div className="text-[#CBD5E1]">• Cipher Algorithm: {sample.cryptoAnalysis.encryptionAlgorithm}</div>
                      <div className="text-[#CBD5E1]">• Confidence Score: {sample.confidenceScore}%</div>
                    </>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-[#0B1220] border border-[#24344D] space-y-2">
                <span className="text-[11px] font-sans font-semibold uppercase tracking-wider text-[#94A3B8]">
                  Limitations &amp; Safety Controls
                </span>
                <div className="space-y-1.5 text-[11px]">
                  {eligibility?.limitations && eligibility.limitations.length > 0 ? (
                    eligibility.limitations.map((lim, i) => (
                      <div key={i} className="flex items-start gap-1.5 text-[#F59E0B]">
                        <span className="shrink-0">•</span>
                        <span>{lim}</span>
                      </div>
                    ))
                  ) : (
                    <>
                      <div className="flex items-start gap-1.5 text-[#F59E0B]">
                        <span className="shrink-0">•</span>
                        <span>Modern ransomware cannot be decrypted without threat actor private keys.</span>
                      </div>
                      <div className="flex items-start gap-1.5 text-[#F59E0B]">
                        <span className="shrink-0">•</span>
                        <span>Zero third-party decryptor binaries are automatically executed.</span>
                      </div>
                      <div className="flex items-start gap-1.5 text-[#22C55E]">
                        <span className="shrink-0">•</span>
                        <span>Original quarantined sample remains immutable and unmodified on disk.</span>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Separate Demo Workbench Callout */}
            <div className="p-3.5 rounded-lg bg-[#16243A] border border-[#A855F7]/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <div className="space-y-0.5">
                <div className="flex items-center gap-1.5 text-[#A855F7] font-semibold">
                  <FlaskConical className="w-4 h-4" />
                  <span>Controlled AES-256-GCM Demonstration Engine</span>
                </div>
                <p className="text-[11px] text-[#94A3B8]">
                  Test encryption, decryption, and integrity verification on isolated test files (.csde format).
                </p>
              </div>
              <button
                onClick={() => onOpenDecryptor(sample)}
                className="px-3 py-2 rounded-lg bg-[#A855F7]/20 hover:bg-[#A855F7]/30 border border-[#A855F7]/40 text-[#A855F7] font-medium text-xs whitespace-nowrap transition"
              >
                Launch Demo Workbench
              </button>
            </div>
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

