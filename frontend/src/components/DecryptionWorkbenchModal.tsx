import React, { useState, useEffect } from 'react';
import { SampleAnalysis } from '../types';
import {
  Key,
  Unlock,
  Download,
  X,
  RefreshCw,
  ShieldCheck,
  Terminal,
  AlertTriangle,
  FlaskConical,
} from 'lucide-react';

interface DecryptionWorkbenchModalProps {
  sample: SampleAnalysis;
  isOpen: boolean;
  onClose: () => void;
}

interface DemoFile {
  filename: string;
  size_bytes: number;
  description: string;
}

interface JobStatus {
  job_id: string;
  status: string;
  verified: boolean;
  output_path: string | null;
  plaintext_sha256: string | null;
  output_sha256: string | null;
  error_message: string | null;
  completed_at: string | null;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export const DecryptionWorkbenchModal: React.FC<DecryptionWorkbenchModalProps> = ({
  sample,
  isOpen,
  onClose,
}) => {
  const [demoFiles, setDemoFiles] = useState<DemoFile[]>([]);
  const [selectedFile, setSelectedFile] = useState('');
  const [encryptedFilename, setEncryptedFilename] = useState('');
  const [demoKey, setDemoKey] = useState('');
  const [userKey, setUserKey] = useState('');

  const [phase, setPhase] = useState<'idle' | 'encrypting' | 'key_display' | 'decrypting' | 'done' | 'error'>('idle');
  const [logs, setLogs] = useState<string[]>([]);
  const [jobResult, setJobResult] = useState<JobStatus | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [recoveredContent, setRecoveredContent] = useState<string | null>(null);

  // Load demo files on open
  useEffect(() => {
    if (!isOpen) return;
    setPhase('idle');
    setLogs([]);
    setJobResult(null);
    setApiError(null);
    setDemoKey('');
    setUserKey('');
    setEncryptedFilename('');
    setRecoveredContent(null);

    fetch(`${API_BASE}/api/v1/decryption/demo/files`)
      .then((r) => r.json())
      .then((data) => {
        const files: DemoFile[] = data.files || [];
        setDemoFiles(files);
        if (files.length > 0) setSelectedFile(files[0].filename);
      })
      .catch(() => {
        setApiError('Could not connect to the CyberShield backend.');
      });
  }, [isOpen]);

  if (!isOpen) return null;

  const appendLog = (line: string) =>
    setLogs((prev) => [...prev, `[${new Date().toISOString().slice(11, 23)}] ${line}`]);

  // Step 1: Encrypt the selected demo file
  const handleEncrypt = async () => {
    if (!selectedFile) return;
    setPhase('encrypting');
    setApiError(null);
    setLogs([]);
    setJobResult(null);
    setDemoKey('');
    setEncryptedFilename('');
    setRecoveredContent(null);
    appendLog(`[DEMO] Encrypting demo file: "${selectedFile}"`);
    appendLog('[CRYPTO] Generating 256-bit AES key via OS CSPRNG...');

    try {
      const resp = await fetch(`${API_BASE}/api/v1/decryption/demo/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ demo_filename: selectedFile }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || `Encryption failed (HTTP ${resp.status})`);
      }

      const data = await resp.json();
      setEncryptedFilename(data.encrypted_filename);
      setDemoKey(data.key_b64);
      setUserKey(data.key_b64);

      appendLog(`[CRYPTO] AES-256-GCM encryption complete.`);
      appendLog(`[FORMAT] Written as CyberShield Demo Encrypted (.csde) format v1`);
      appendLog(`[HASH] Plaintext SHA-256: ${data.plaintext_sha256?.slice(0, 16)}...`);
      appendLog(`[KEY] Key generated — displayed below. NOT stored by server.`);
      setPhase('key_display');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendLog(`[ERROR] ${msg}`);
      setApiError(msg);
      setPhase('error');
    }
  };

  // Step 2: Decrypt with the provided key
  const handleDecrypt = async () => {
    if (!encryptedFilename || !userKey) return;
    setPhase('decrypting');
    setApiError(null);
    setJobResult(null);
    setRecoveredContent(null);
    appendLog(`[DEMO] Submitting decryption job for: "${encryptedFilename}"`);
    appendLog('[AUTH] AES-256-GCM authenticated decryption in progress...');

    try {
      const resp = await fetch(`${API_BASE}/api/v1/decryption/demo/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          encrypted_filename: encryptedFilename,
          key_b64: userKey,
          sample_id: sample?.id || undefined,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || `Decryption failed (HTTP ${resp.status})`);
      }

      const job: JobStatus = await resp.json();
      setJobResult(job);

      if (job.status === 'RECOVERY_SUCCEEDED' && job.verified) {
        appendLog('[GCM] Authentication tag verified ✓');
        appendLog('[INTEGRITY] SHA-256 of recovered file matches original ✓');
        appendLog(`[OUTPUT] Recovered file: ${job.output_path}`);
        appendLog(`[STATUS] RECOVERY_SUCCEEDED — integrity verified`);
        setRecoveredContent(
          `Recovery Status : SUCCEEDED\n` +
          `Verified        : ${job.verified}\n` +
          `Output file     : ${job.output_path}\n` +
          `Plaintext SHA-256: ${job.plaintext_sha256}\n` +
          `Output SHA-256  : ${job.output_sha256}\n` +
          `Completed at    : ${job.completed_at}`
        );
      } else if (job.status === 'RECOVERY_FAILED') {
        appendLog(`[FAILED] ${job.error_message || 'Decryption failed.'}`);
        appendLog('[NOTE] This is expected when an incorrect key is supplied.');
        setApiError(job.error_message || 'Decryption failed. Check the key and try again.');
      } else {
        appendLog(`[STATUS] ${job.status}`);
        if (job.error_message) setApiError(job.error_message);
      }
      setPhase('done');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendLog(`[ERROR] ${msg}`);
      setApiError(msg);
      setPhase('done');
    }
  };

  const isSucceeded = jobResult?.status === 'RECOVERY_SUCCEEDED' && jobResult?.verified;
  const isFailed = phase === 'done' && !isSucceeded;

  const downloadRecoveredFile = async () => {
    if (!jobResult?.job_id) return;
    try {
      const resp = await fetch(
        `${API_BASE}/api/v1/decryption/demo/jobs/${jobResult.job_id}/download`
      );
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: `HTTP ${resp.status}` }));
        appendLog(`[ERROR] Download failed: ${err.detail || resp.statusText}`);
        return;
      }
      const blob = await resp.blob();
      // Prefer the filename from Content-Disposition, fall back to output_path basename.
      const disposition = resp.headers.get('content-disposition') || '';
      const filenameMatch = disposition.match(/filename[^;=\n]*=(?:(['"])([^'"]*)\1|([^;\n]*))/);
      const filename =
        (filenameMatch?.[2] || filenameMatch?.[3])?.trim() ||
        jobResult.output_path?.split(/[\\/]/).pop() ||
        `recovered_${jobResult.job_id.slice(0, 8)}.bin`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      appendLog(`[DOWNLOAD] File saved: ${filename} (${blob.size} bytes)`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendLog(`[ERROR] Download error: ${msg}`);
    }
  };

  const busy = phase === 'encrypting' || phase === 'decrypting';

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#111C2E] border border-[#24344D] rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">

        {/* Header */}
        <div className="p-4 border-b border-[#24344D] flex items-center justify-between bg-[#16243A]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-[#3B82F6]/10 text-[#3B82F6] border border-[#3B82F6]/20">
              <Key className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-[#F8FAFC]">
                Decryption Workbench
                <span className="ml-2 text-[10px] font-normal text-amber-400 border border-amber-400/30 bg-amber-400/10 rounded px-1.5 py-0.5">
                  CONTROLLED DEMO
                </span>
              </h2>
              <p className="text-xs text-[#94A3B8]">
                Target Strain: <span className="text-[#F8FAFC] font-medium">{sample.ransomwareFamily}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#24344D] transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">

          {/* Demo notice */}
          <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-amber-300 text-[11px] font-sans">
            <FlaskConical className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>
              <strong>Controlled demo only.</strong> This workbench encrypts a provided demo file
              with a real AES-256-GCM key and then decrypts it. It does NOT decrypt ransomware samples
              and does NOT claim to recover real encrypted victim files.
            </span>
          </div>

          {/* Step 1: Select demo file and encrypt */}
          {(phase === 'idle' || phase === 'error') && (
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-[#94A3B8] text-[11px] font-medium uppercase tracking-wider block font-sans">
                  1. Select Demo File to Encrypt
                </label>
                <select
                  value={selectedFile}
                  onChange={(e) => setSelectedFile(e.target.value)}
                  disabled={demoFiles.length === 0}
                  className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs font-mono focus:border-[#3B82F6] outline-none cursor-pointer"
                >
                  {demoFiles.length === 0
                    ? <option>Loading demo files...</option>
                    : demoFiles.map((f) => (
                        <option key={f.filename} value={f.filename}>
                          {f.filename} ({(f.size_bytes / 1024).toFixed(1)} KB)
                        </option>
                      ))
                  }
                </select>
              </div>
              <button
                onClick={handleEncrypt}
                disabled={!selectedFile || busy}
                className="w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 bg-[#3B82F6] hover:bg-blue-600 text-white transition disabled:opacity-50 disabled:cursor-not-allowed font-sans"
              >
                <Key className="w-3.5 h-3.5" />
                <span>Encrypt Demo File (Generate Key)</span>
              </button>
            </div>
          )}

          {/* Step 2: Key display and decrypt */}
          {(phase === 'key_display' || phase === 'decrypting' || phase === 'done') && (
            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/30 space-y-2">
                <div className="flex items-center gap-1.5 text-amber-300 font-sans text-[11px] font-semibold">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Demo Key — Save this now. The server does NOT store it.
                </div>
                <div className="font-mono text-[11px] text-[#22C55E] break-all bg-[#0B1220] rounded p-2 border border-[#24344D]">
                  {demoKey}
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex items-center justify-between font-sans">
                  <label className="text-[#94A3B8] text-[11px] font-medium uppercase tracking-wider">
                    2. Enter Key to Decrypt (edit to test wrong-key rejection)
                  </label>
                </div>
                <input
                  type="text"
                  value={userKey}
                  onChange={(e) => setUserKey(e.target.value)}
                  disabled={busy || phase === 'done'}
                  className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#3B82F6] font-mono text-xs focus:border-[#3B82F6] outline-none disabled:opacity-60"
                  placeholder="Paste your demo key here..."
                />
              </div>

              {phase !== 'done' && (
                <button
                  onClick={handleDecrypt}
                  disabled={busy || !userKey}
                  className={`w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 transition font-sans ${
                    busy
                      ? 'bg-[#16243A] text-[#94A3B8] cursor-not-allowed border border-[#24344D]'
                      : 'bg-[#3B82F6] hover:bg-blue-600 text-white'
                  }`}
                >
                  {busy ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#3B82F6]" />
                      <span>Decrypting...</span>
                    </>
                  ) : (
                    <>
                      <Unlock className="w-3.5 h-3.5" />
                      <span>Run Authenticated Decryption</span>
                    </>
                  )}
                </button>
              )}

              {/* Reset button */}
              {phase === 'done' && (
                <button
                  onClick={() => {
                    setPhase('idle');
                    setLogs([]);
                    setJobResult(null);
                    setApiError(null);
                    setDemoKey('');
                    setUserKey('');
                    setEncryptedFilename('');
                    setRecoveredContent(null);
                  }}
                  className="w-full py-2 rounded-lg font-medium text-xs flex items-center justify-center gap-2 border border-[#24344D] text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#16243A] transition font-sans"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Run Another Demo</span>
                </button>
              )}
            </div>
          )}

          {/* Worker trace log */}
          <div className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D] space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-[#94A3B8] pb-1 border-b border-[#24344D]">
              <span className="flex items-center gap-1.5 text-[#3B82F6] font-medium">
                <Terminal className="w-3.5 h-3.5" /> Decryptor Worker Trace
              </span>
              <span className="text-[10px] text-[#22C55E]">AES-256-GCM (NIST)</span>
            </div>
            <div className="h-24 overflow-y-auto space-y-1 text-[11px] text-[#F8FAFC] font-mono">
              {logs.length === 0 ? (
                <div className="text-[#94A3B8]/60 italic text-center py-3">
                  Awaiting demo operation...
                </div>
              ) : (
                logs.map((log, i) => (
                  <div
                    key={i}
                    className={
                      log.includes('SUCCEEDED') || log.includes('✓')
                        ? 'text-[#22C55E] font-medium'
                        : log.includes('ERROR') || log.includes('FAILED')
                        ? 'text-red-400'
                        : 'text-[#94A3B8]'
                    }
                  >
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* API error */}
          {apiError && (
            <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/30 flex items-start gap-2 text-[11px] text-red-300 font-sans">
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
              <span>{apiError}</span>
            </div>
          )}

          {/* Success result */}
          {isSucceeded && recoveredContent && (
            <div className="p-3.5 rounded-lg bg-[#0B1220] border border-[#22C55E]/40 space-y-2.5 animate-in fade-in">
              <div className="flex items-center justify-between font-sans">
                <span className="text-xs font-medium text-[#22C55E] flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5" /> Recovery Verified — Output Integrity Confirmed
                </span>
                <button
                  onClick={downloadRecoveredFile}
                  className="px-2.5 py-1 rounded bg-[#22C55E] hover:bg-green-600 text-slate-950 font-medium text-[11px] flex items-center gap-1 transition"
                >
                  <Download className="w-3 h-3" />
                  <span>Download File</span>
                </button>
              </div>
              <pre className="p-2.5 rounded bg-[#111C2E] border border-[#24344D] text-[#F8FAFC] text-[11px] font-mono whitespace-pre-wrap max-h-32 overflow-y-auto">
                {recoveredContent}
              </pre>
            </div>
          )}

          {/* Explicit failure result */}
          {isFailed && !isSucceeded && jobResult && (
            <div className="p-3.5 rounded-lg bg-[#0B1220] border border-red-500/30 space-y-1.5 font-sans">
              <div className="text-xs font-medium text-red-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> Recovery Failed — {jobResult.status}
              </div>
              <p className="text-[11px] text-[#94A3B8]">
                This is the expected outcome when an incorrect key is supplied.
                The AES-GCM authentication tag rejected the key before any data was released.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
