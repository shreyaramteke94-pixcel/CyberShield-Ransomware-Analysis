import React, { useState, useRef, useEffect } from 'react';
import { SampleAnalysis } from '../types';
import { PRESET_MALWARE_SAMPLES } from '../data/mockData';
import { 
  UploadCloud, 
  FileCode, 
  CheckCircle2, 
  Play, 
  RefreshCw, 
  Terminal,
  FileCheck
} from 'lucide-react';

interface UploadViewProps {
  onAnalysisComplete: (sample: SampleAnalysis) => void;
  existingSamples: SampleAnalysis[];
}

export const UploadView: React.FC<UploadViewProps> = ({
  onAnalysisComplete,
  existingSamples
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<{
    name: string;
    size: string;
    type: string;
    rawFile?: File;
    sampleRefId?: string;
  } | null>({
    name: 'LB3_Black_payload_x64.exe',
    size: '412.8 KB',
    type: 'PE32+ executable (x86-64)',
    sampleRefId: 'SMP-LB3-9901'
  });

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [logs, setLogs] = useState<string[]>([]);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const analysisSteps = [
    { id: 1, name: 'Quarantine Ingestion', desc: 'Secure hash & metadata calculation' },
    { id: 2, name: 'Static Dissection', desc: 'Header entropy & YARA matching' },
    { id: 3, name: 'Dynamic Detonation', desc: 'Sandbox runtime behavioral trace' },
    { id: 4, name: 'Cryptographic Probe', desc: 'Key derivation & algorithm testing' },
    { id: 5, name: 'ML Classification', desc: 'Ensemble model heuristic inference' },
    { id: 6, name: 'Report Generation', desc: 'Compiling mitigation artifacts' },
  ];

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile({
        name: file.name,
        size: `${(file.size / 1024).toFixed(1)} KB`,
        type: file.type || 'Binary / Unknown',
        rawFile: file
      });
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile({
        name: file.name,
        size: `${(file.size / 1024).toFixed(1)} KB`,
        type: file.type || 'Binary / Executable',
        rawFile: file
      });
    }
  };

  const handleSelectPreset = (preset: typeof PRESET_MALWARE_SAMPLES[0]) => {
    setSelectedFile({
      name: preset.name,
      size: preset.size,
      type: preset.type,
      sampleRefId: preset.sampleId
    });
  };

  const startAnalysis = () => {
    if (!selectedFile || isAnalyzing) return;

    setIsAnalyzing(true);
    setCurrentStep(1);
    setLogs([
      `[00:00.001] [INIT] Ingesting file payload: "${selectedFile.name}" (${selectedFile.size})`,
      `[00:00.040] [SHA256] Calculating cryptographic hashes in secure quarantine sandbox...`,
      `[00:00.120] [HASH] MD5: 7d8b92d6e3c114f09d842a19e88cb921`,
      `[00:00.180] [HASH] SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`
    ]);

    setTimeout(() => {
      setCurrentStep(2);
      setLogs((prev) => [
        ...prev,
        `[00:00.450] [STATIC] Parsing Portable Executable (PE32+) header architecture...`,
        `[00:00.620] [STATIC] Calculated Shannon Entropy: 7.94 / 8.0 (High Packing / Encrypted Sections)`,
        `[00:00.780] [STATIC] Flagged suspicious import: CryptAcquireContextW`,
        `[00:01.050] [STATIC] YARA signature matched: "CyberShield_Ransomware_LockBit3"`
      ]);
    }, 1100);

    setTimeout(() => {
      setCurrentStep(3);
      setLogs((prev) => [
        ...prev,
        `[00:01.300] [DYNAMIC] Spawning process under virtual API hook monitor...`,
        `[00:01.780] [DYNAMIC] DETECTED: Anti-Analysis check bypass`,
        `[00:01.990] [DYNAMIC] DETECTED: Spawned "vssadmin.exe Delete Shadows /All /Quiet"`,
        `[00:02.150] [DYNAMIC] DETECTED: Mass WriteFile operations - modifying files with ransomware extension`
      ]);
    }, 2200);

    setTimeout(() => {
      setCurrentStep(4);
      setLogs((prev) => [
        ...prev,
        `[00:02.600] [CRYPTO] Probing cryptographic primitives and key schedule...`,
        `[00:02.810] [CRYPTO] Identified Algorithm: AES-256-CBC with Curve25519 asymmetric envelope`,
        `[00:03.010] [CRYPTO] VULNERABILITY DETECTED: Flawed PRNG seed initialization!`,
        `[00:03.350] [CRYPTO] Decryption Feasibility Status: DECRYPTABLE (98.2% recovery rate)`
      ]);
    }, 3300);

    setTimeout(() => {
      setCurrentStep(5);
      setLogs((prev) => [
        ...prev,
        `[00:03.600] [ML] Executing CyberShield DeepMalwareNet Ensemble...`,
        `[00:03.820] [ML] Verdict: LockBit 3.0 (Probability: 96.8%)`,
        `[00:03.950] [ML] Threat Severity: CRITICAL`
      ]);
    }, 4300);

    setTimeout(() => {
      setCurrentStep(6);
      setLogs((prev) => [
        ...prev,
        `[00:04.200] [REPORT] Synthesizing comprehensive CyberShield analysis report...`,
        `[00:04.400] [SUCCESS] Analysis complete! Loading results.`
      ]);

      setTimeout(() => {
        setIsAnalyzing(false);
        let matched = existingSamples.find(s => s.id === selectedFile.sampleRefId);
        if (!matched) {
          if (selectedFile.name.toLowerCase().includes('wannacry')) {
            matched = existingSamples.find(s => s.id === 'SMP-WCR-2017');
          } else if (selectedFile.name.toLowerCase().includes('blackcat') || selectedFile.name.toLowerCase().includes('alphv')) {
            matched = existingSamples.find(s => s.id === 'SMP-BLK-4402');
          } else if (selectedFile.name.toLowerCase().includes('safe') || selectedFile.name.toLowerCase().includes('audit') || selectedFile.name.toLowerCase().includes('xlsx')) {
            matched = existingSamples.find(s => s.id === 'SMP-SAF-1008');
          } else {
            matched = existingSamples[0];
          }
        }
        if (matched) {
          onAnalysisComplete(matched);
        }
      }, 800);
    }, 5200);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12" id="cybershield-upload-page">
      {/* Page Header */}
      <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D]">
        <h1 className="text-xl font-semibold text-[#F8FAFC]">Upload &amp; Analyze Sample</h1>
        <p className="text-xs text-[#94A3B8] mt-0.5">
          Submit suspicious executables, documents, or scripts for static inspection and sandbox detonation
        </p>
      </div>

      {/* Preset Quick Selectors */}
      <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-2.5">
        <div className="flex items-center justify-between text-xs">
          <span className="text-[#94A3B8] font-medium">Quick Test Vectors:</span>
          <span className="text-[#94A3B8]/70 text-[11px]">Select a sample to populate test payload</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {PRESET_MALWARE_SAMPLES.map((preset) => {
            const isSelected = selectedFile?.sampleRefId === preset.sampleId;
            const isSafe = preset.name.includes('xlsx');
            return (
              <button
                key={preset.sampleId}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                className={`p-3 rounded-lg text-left transition border text-xs ${
                  isSelected
                    ? 'bg-[#16243A] border-[#3B82F6] text-[#F8FAFC]'
                    : 'bg-[#0B1220] border-[#24344D] text-[#94A3B8] hover:border-[#3B82F6]/50 hover:text-[#F8FAFC]'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`text-[10px] font-medium px-1.5 py-0.2 rounded ${
                    isSafe ? 'bg-[#22C55E]/15 text-[#22C55E]' : 'bg-[#EF4444]/15 text-[#EF4444]'
                  }`}>
                    {isSafe ? 'Clean' : 'Malware'}
                  </span>
                  <span className="text-[10px] text-[#94A3B8] font-mono">{preset.size}</span>
                </div>
                <div className="font-medium text-[#F8FAFC] truncate">{preset.name}</div>
                <div className="text-[11px] text-[#94A3B8] truncate mt-0.5">{preset.description}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Upload Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Upload Container */}
        <div className="lg:col-span-7 space-y-4">
          <div
            id="sample-dropzone"
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`p-8 rounded-xl border-2 border-dashed transition flex flex-col items-center justify-center text-center ${
              dragActive
                ? 'border-[#3B82F6] bg-[#16243A]'
                : selectedFile
                ? 'border-[#24344D] bg-[#111C2E]'
                : 'border-[#24344D] bg-[#111C2E] hover:border-[#3B82F6]/60'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileChange}
              className="hidden"
              id="file-upload-input"
            />

            <div className="p-3 rounded-lg bg-[#16243A] border border-[#24344D] text-[#3B82F6] mb-3">
              <UploadCloud className="w-8 h-8" />
            </div>

            <h3 className="text-sm font-semibold text-[#F8FAFC]">
              Drag &amp; drop sample file, or{' '}
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="text-[#3B82F6] hover:underline font-medium"
              >
                Browse
              </button>
            </h3>

            <p className="text-xs text-[#94A3B8] mt-1 max-w-sm">
              Supports PE (.exe, .dll), scripts, office documents, and compressed archives.
            </p>

            <div className="mt-3 flex items-center gap-2 text-[11px] text-[#94A3B8]">
              <span>Max: 100 MB</span>
              <span>•</span>
              <span>Air-Gapped Sandbox</span>
            </div>
          </div>

          {/* Selected File Details Box */}
          {selectedFile && (
            <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#24344D]">
                <span className="text-xs font-medium text-[#F8FAFC] flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-[#3B82F6]" /> File Details
                </span>
                <span className="text-[10px] font-medium text-[#22C55E] bg-[#22C55E]/10 px-2 py-0.5 rounded">
                  Ready to detonate
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                <div>
                  <span className="text-[#94A3B8] text-[10px] uppercase">Name:</span>
                  <div className="text-[#F8FAFC] font-medium truncate">{selectedFile.name}</div>
                </div>
                <div>
                  <span className="text-[#94A3B8] text-[10px] uppercase">Size:</span>
                  <div className="text-[#F8FAFC] font-medium font-mono">{selectedFile.size}</div>
                </div>
                <div>
                  <span className="text-[#94A3B8] text-[10px] uppercase">Format:</span>
                  <div className="text-[#F8FAFC] font-medium truncate">{selectedFile.type}</div>
                </div>
              </div>

              {/* Action Button */}
              <button
                id="analyze-sample-btn"
                type="button"
                disabled={isAnalyzing}
                onClick={startAnalysis}
                className={`w-full py-2.5 px-4 rounded-lg font-medium text-xs tracking-wider flex items-center justify-center gap-2 transition ${
                  isAnalyzing
                    ? 'bg-[#16243A] text-[#94A3B8] cursor-not-allowed border border-[#24344D]'
                    : 'bg-[#3B82F6] hover:bg-blue-600 text-white'
                }`}
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#3B82F6]" />
                    Analyzing Sample...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    Start Detonation &amp; Analysis
                  </>
                )}
              </button>
            </div>
          )}
        </div>

        {/* Live Analysis Progress Pipeline */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#24344D]">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
                Analysis Stages
              </h2>
              <span className="text-[11px] font-mono text-[#3B82F6]">
                {currentStep > 0 ? `Stage ${currentStep}/6` : 'Standby'}
              </span>
            </div>

            {/* Steps List */}
            <div className="space-y-2 text-xs">
              {analysisSteps.map((step) => {
                const isPassed = currentStep > step.id;
                const isCurrent = currentStep === step.id;

                return (
                  <div
                    key={step.id}
                    className={`p-2.5 rounded-lg border transition flex items-start gap-2.5 ${
                      isCurrent
                        ? 'bg-[#16243A] border-[#3B82F6] text-[#F8FAFC]'
                        : isPassed
                        ? 'bg-[#111C2E] border-[#24344D] text-[#F8FAFC]'
                        : 'bg-[#0B1220] border-[#24344D]/50 text-[#94A3B8]'
                    }`}
                  >
                    <div className={`mt-0.5 w-4 h-4 rounded-full text-[10px] font-bold flex items-center justify-center ${
                      isPassed
                        ? 'text-[#22C55E]'
                        : isCurrent
                        ? 'text-[#3B82F6]'
                        : 'text-[#94A3B8]'
                    }`}>
                      {isPassed ? (
                        <CheckCircle2 className="w-4 h-4 text-[#22C55E]" />
                      ) : (
                        <span>{step.id}</span>
                      )}
                    </div>

                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className={`font-medium ${isCurrent ? 'text-[#3B82F6]' : isPassed ? 'text-[#F8FAFC]' : 'text-[#94A3B8]'}`}>
                          {step.name}
                        </span>
                        {isCurrent && (
                          <span className="text-[10px] text-[#3B82F6] font-medium">Running...</span>
                        )}
                        {isPassed && (
                          <span className="text-[10px] text-[#22C55E]">Done</span>
                        )}
                      </div>
                      <p className="text-[11px] text-[#94A3B8] mt-0.5">{step.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Real-time Detonation Console */}
          <div className="p-3.5 rounded-xl bg-[#0B1220] border border-[#24344D] font-mono text-xs space-y-2">
            <div className="flex items-center justify-between text-[11px] text-[#94A3B8] pb-1 border-b border-[#24344D]">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-[#3B82F6]" /> Detonation Console
              </span>
              <span className="w-2 h-2 rounded-full bg-[#22C55E]" />
            </div>

            <div
              ref={logContainerRef}
              className="h-32 overflow-y-auto space-y-1 text-[11px] font-mono scroll-smooth"
            >
              {logs.length === 0 ? (
                <div className="text-[#94A3B8]/60 italic py-6 text-center">
                  Awaiting sample submission...
                </div>
              ) : (
                logs.map((log, idx) => (
                  <div 
                    key={idx} 
                    className={
                      log.includes('CRITICAL') || log.includes('DETECTED') 
                        ? 'text-[#EF4444]' 
                        : log.includes('VULNERABILITY') || log.includes('DECRYPTABLE')
                        ? 'text-[#22D3EE]'
                        : log.includes('SUCCESS')
                        ? 'text-[#22C55E]'
                        : 'text-[#94A3B8]'
                    }
                  >
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

