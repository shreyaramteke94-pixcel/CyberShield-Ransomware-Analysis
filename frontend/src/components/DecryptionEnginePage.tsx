import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Key, Unlock, RefreshCw, ShieldCheck, Shield,
  AlertTriangle, FlaskConical, Database, ChevronRight,
  CheckCircle, XCircle, Clock, Info, Upload, Download, FolderOpen,
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

// -------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------

interface DemoFile {
  filename: string;
  size_bytes: number;
  description: string;
}

interface AdapterInfo {
  adapter_id: string;
  display_name: string;
  source: string;
  supported_families: string[];
  status: string;
  prerequisites: string[];
  limitations: string[];
  can_run_automatically: boolean;
  requires_explicit_approval: boolean;
}

interface JobRecord {
  job_id: string;
  job_type: string;
  status: string;
  verified: boolean;
  input_file: string | null;
  output_path: string | null;
  plaintext_sha256: string | null;
  output_sha256: string | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

// -------------------------------------------------------------------------
// Helper components
// -------------------------------------------------------------------------

function StatusBadge({ status, verified }: { status: string; verified: boolean }) {
  const map: Record<string, { color: string; icon: React.ReactNode }> = {
    RECOVERY_SUCCEEDED: { color: 'text-[#22C55E] border-[#22C55E]/30 bg-[#22C55E]/5', icon: <CheckCircle className="w-3 h-3" /> },
    OUTPUT_VERIFICATION_FAILED: { color: 'text-amber-400 border-amber-400/30 bg-amber-400/5', icon: <AlertTriangle className="w-3 h-3" /> },
    RECOVERY_FAILED: { color: 'text-red-400 border-red-400/30 bg-red-400/5', icon: <XCircle className="w-3 h-3" /> },
    RECOVERY_IN_PROGRESS: { color: 'text-[#3B82F6] border-[#3B82F6]/30 bg-[#3B82F6]/5', icon: <RefreshCw className="w-3 h-3 animate-spin" /> },
    READY_FOR_RECOVERY: { color: 'text-cyan-400 border-cyan-400/30 bg-cyan-400/5', icon: <Clock className="w-3 h-3" /> },
  };
  const s = map[status] || { color: 'text-[#94A3B8] border-[#24344D] bg-[#16243A]', icon: <Info className="w-3 h-3" /> };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-medium font-mono ${s.color}`}>
      {s.icon}
      {status}
      {status === 'RECOVERY_SUCCEEDED' && !verified && ' (unverified)'}
    </span>
  );
}

function AdapterStatusDot({ status }: { status: string }) {
  if (status === 'AVAILABLE') return <span className="w-2 h-2 rounded-full bg-[#22C55E] inline-block" />;
  if (status === 'REQUIRES_PREREQUISITES') return <span className="w-2 h-2 rounded-full bg-amber-400 inline-block" />;
  return <span className="w-2 h-2 rounded-full bg-[#94A3B8]/40 inline-block" />;
}

// -------------------------------------------------------------------------
// Main Page
// -------------------------------------------------------------------------

export const DecryptionEnginePage: React.FC = () => {
  // Tabs: 'demo' | 'registry' | 'jobs'
  const [activeSection, setActiveSection] = useState<'demo' | 'registry' | 'jobs'>('demo');

  // Demo source mode: 'preset' = 3 demo files, 'custom' = upload your own
  const [sourceMode, setSourceMode] = useState<'preset' | 'custom'>('preset');

  // Preset demo state
  const [demoFiles, setDemoFiles] = useState<DemoFile[]>([]);
  const [selectedFile, setSelectedFile] = useState('');

  // Custom file state
  const [customFile, setCustomFile] = useState<File | null>(null);
  const [customFileInfo, setCustomFileInfo] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Shared encrypted-file upload state
  const [uploadedCsdeFile, setUploadedCsdeFile] = useState<File | null>(null);
  const csdeInputRef = useRef<HTMLInputElement>(null);

  // Shared workflow state
  const [demoKey, setDemoKey] = useState('');
  const [userKey, setUserKey] = useState('');
  const [encryptedFilename, setEncryptedFilename] = useState('');
  const [demoPhase, setDemoPhase] = useState<'idle' | 'encrypting' | 'key_display' | 'uploading_csde' | 'decrypting' | 'done'>('idle');
  const [demoLogs, setDemoLogs] = useState<string[]>([]);
  const [demoJob, setDemoJob] = useState<JobRecord | null>(null);
  const [demoError, setDemoError] = useState<string | null>(null);

  // Registry state
  const [adapters, setAdapters] = useState<AdapterInfo[]>([]);
  const [registryLoading, setRegistryLoading] = useState(false);

  // Jobs state
  const [jobs, setJobs] = useState<JobRecord[]>([]);
  const [jobsLoading, setJobsLoading] = useState(false);

  // Load demo files on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/v1/decryption/demo/files`)
      .then((r) => r.json())
      .then((d) => {
        const files: DemoFile[] = d.files || [];
        setDemoFiles(files);
        if (files.length > 0) setSelectedFile(files[0].filename);
      })
      .catch(() => setDemoError('Cannot reach CyberShield backend.'));
  }, []);

  const loadRegistry = useCallback(() => {
    setRegistryLoading(true);
    fetch(`${API_BASE}/api/v1/decryption/registry`)
      .then((r) => r.json())
      .then((d) => setAdapters(d.adapters || []))
      .finally(() => setRegistryLoading(false));
  }, []);

  const loadJobs = useCallback(() => {
    setJobsLoading(true);
    fetch(`${API_BASE}/api/v1/decryption/demo/jobs`)
      .then((r) => r.json())
      .then((d) => setJobs(Array.isArray(d) ? d : []))
      .finally(() => setJobsLoading(false));
  }, []);

  useEffect(() => {
    if (activeSection === 'registry') loadRegistry();
    if (activeSection === 'jobs') loadJobs();
  }, [activeSection, loadRegistry, loadJobs]);

  const appendDemoLog = (line: string) =>
    setDemoLogs((prev) => [...prev, `[${new Date().toISOString().slice(11, 23)}] ${line}`]);

  const resetDemo = () => {
    setDemoPhase('idle');
    setDemoLogs([]);
    setDemoJob(null);
    setDemoError(null);
    setDemoKey('');
    setUserKey('');
    setEncryptedFilename('');
    setCustomFile(null);
    setCustomFileInfo('');
    setUploadedCsdeFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (csdeInputRef.current) csdeInputRef.current.value = '';
  };

  // --- Preset demo encrypt (unchanged) ---
  const handleEncryptPreset = async () => {
    if (!selectedFile) return;
    setDemoPhase('encrypting');
    setDemoError(null);
    setDemoLogs([]);
    setDemoJob(null);
    appendDemoLog(`[DEMO] Encrypting preset file: "${selectedFile}"`);
    appendDemoLog('[CRYPTO] Generating 256-bit AES key via OS CSPRNG (os.urandom)...');
    try {
      const resp = await fetch(`${API_BASE}/api/v1/decryption/demo/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ demo_filename: selectedFile }),
      });
      if (!resp.ok) {
        const e = await resp.json();
        throw new Error(e.detail || `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      setEncryptedFilename(data.encrypted_filename);
      setDemoKey(data.key_b64);
      setUserKey(data.key_b64);
      appendDemoLog('[CRYPTO] AES-256-GCM encryption complete.');
      appendDemoLog(`[FORMAT] CyberShield Demo Encrypted (.csde) format v1`);
      appendDemoLog(`[HASH] Plaintext SHA-256: ${(data.plaintext_sha256 || '').slice(0, 24)}...`);
      appendDemoLog('[KEY] Demo key generated — displayed below. NOT stored server-side.');
      setDemoPhase('key_display');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendDemoLog(`[ERROR] ${msg}`);
      setDemoError(msg);
      setDemoPhase('idle');
    }
  };

  // --- Custom file encrypt ---
  const handleEncryptCustomFile = async () => {
    if (!customFile) return;
    setDemoPhase('encrypting');
    setDemoError(null);
    setDemoLogs([]);
    setDemoJob(null);
    appendDemoLog(`[CUSTOM] Encrypting uploaded file: "${customFile.name}" (${customFile.size} bytes)`);
    appendDemoLog('[CRYPTO] Generating 256-bit AES key via OS CSPRNG (os.urandom)...');
    try {
      const formData = new FormData();
      formData.append('file', customFile);
      const resp = await fetch(`${API_BASE}/api/v1/decryption/custom/encrypt`, {
        method: 'POST',
        body: formData,
      });
      if (!resp.ok) {
        const e = await resp.json();
        throw new Error(e.detail || `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      setEncryptedFilename(data.encrypted_filename);
      setDemoKey(data.key_b64);
      setUserKey(data.key_b64);
      appendDemoLog('[CRYPTO] AES-256-GCM encryption complete.');
      appendDemoLog(`[FORMAT] CyberShield Demo Encrypted (.csde) format v1`);
      appendDemoLog(`[HASH] Plaintext SHA-256: ${(data.plaintext_sha256 || '').slice(0, 24)}...`);
      appendDemoLog('[KEY] Demo key generated — displayed below. NOT stored server-side.');
      setDemoPhase('key_display');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendDemoLog(`[ERROR] ${msg}`);
      setDemoError(msg);
      setDemoPhase('idle');
    }
  };

  // --- Upload pre-existing .csde file ---
  const handleUploadCsde = async () => {
    if (!uploadedCsdeFile) return;
    setDemoPhase('uploading_csde');
    setDemoError(null);
    setDemoLogs([]);
    setDemoJob(null);
    appendDemoLog(`[UPLOAD] Validating uploaded .csde file: "${uploadedCsdeFile.name}"`);
    try {
      const formData = new FormData();
      formData.append('file', uploadedCsdeFile);
      const resp = await fetch(`${API_BASE}/api/v1/decryption/custom/upload-encrypted`, {
        method: 'POST',
        body: formData,
      });
      if (!resp.ok) {
        const e = await resp.json();
        throw new Error(e.detail || `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      setEncryptedFilename(data.encrypted_filename);
      appendDemoLog('[UPLOAD] Magic bytes validated (CSDE v1). File saved.');
      appendDemoLog(`[FILE] Encrypted filename: ${data.encrypted_filename}`);
      appendDemoLog('[STEP] Enter your saved key below to decrypt.');
      setDemoPhase('key_display');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendDemoLog(`[ERROR] ${msg}`);
      setDemoError(msg);
      setDemoPhase('idle');
    }
  };

  // --- Decrypt (shared for both modes) ---
  const handleDecrypt = async () => {
    if (!encryptedFilename || !userKey) return;
    setDemoPhase('decrypting');
    setDemoError(null);
    appendDemoLog(`[DEMO] Submitting decryption job for: "${encryptedFilename}"`);
    appendDemoLog('[AUTH] AES-256-GCM authenticated decryption...');
    try {
      const resp = await fetch(`${API_BASE}/api/v1/decryption/demo/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_filename: encryptedFilename, key_b64: userKey }),
      });
      if (!resp.ok) {
        const e = await resp.json();
        throw new Error(e.detail || `HTTP ${resp.status}`);
      }
      const job: JobRecord = await resp.json();
      setDemoJob(job);
      if (job.status === 'RECOVERY_SUCCEEDED' && job.verified) {
        appendDemoLog('[GCM] Authentication tag: VALID ✓');
        appendDemoLog('[INTEGRITY] SHA-256 match: PASS ✓');
        appendDemoLog(`[STATUS] RECOVERY_SUCCEEDED — integrity verified`);
      } else if (job.status === 'RECOVERY_FAILED') {
        appendDemoLog(`[FAILED] ${job.error_message || 'Authentication failed.'}`);
        appendDemoLog('[NOTE] Correct behavior — wrong key rejected before plaintext release.');
        setDemoError(job.error_message || 'Decryption failed.');
      } else {
        appendDemoLog(`[STATUS] ${job.status}`);
      }
      setDemoPhase('done');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendDemoLog(`[ERROR] ${msg}`);
      setDemoError(msg);
      setDemoPhase('done');
    }
  };

  // --- Download recovered file ---
  const handleDownloadRecovered = async () => {
    if (!demoJob?.job_id) return;
    try {
      const resp = await fetch(`${API_BASE}/api/v1/decryption/demo/jobs/${demoJob.job_id}/download`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const blob = await resp.blob();
      const cd = resp.headers.get('content-disposition') || '';
      const fnMatch = cd.match(/filename="?([^";]+)"?/);
      const filename = fnMatch ? fnMatch[1] : (demoJob.output_path || 'recovered_file');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setDemoError(`Download failed: ${msg}`);
    }
  };

  // --- Download encrypted .csde file ---
  const handleDownloadEncrypted = async () => {
    if (!encryptedFilename) return;
    try {
      const resp = await fetch(
        `${API_BASE}/api/v1/decryption/custom/encrypted/${encodeURIComponent(encryptedFilename)}/download`
      );
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = encryptedFilename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setDemoError(`Encrypted file download failed: ${msg}`);
    }
  };

  const demoBusy = demoPhase === 'encrypting' || demoPhase === 'decrypting' || demoPhase === 'uploading_csde';
  const demoSucceeded = demoJob?.status === 'RECOVERY_SUCCEEDED' && demoJob?.verified;

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold text-[#F8FAFC] flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[#3B82F6]/10 border border-[#3B82F6]/20 text-[#3B82F6]">
            <Key className="w-5 h-5" />
          </div>
          Decryption Engine
        </h1>
        <p className="text-sm text-[#94A3B8] mt-1">
          Controlled AES-256-GCM demonstration and ransomware recovery eligibility check.
        </p>
      </div>

      {/* Section tabs */}
      <div className="flex gap-1 p-1 bg-[#111C2E] rounded-lg border border-[#24344D]">
        {([
          { id: 'demo', label: 'Demo Workbench', icon: FlaskConical },
          { id: 'registry', label: 'Decryptor Registry', icon: Database },
          { id: 'jobs', label: 'Job History', icon: Clock },
        ] as const).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveSection(id)}
            className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded text-xs font-medium transition ${activeSection === id
                ? 'bg-[#16243A] text-[#F8FAFC] border border-[#3B82F6]/30'
                : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#16243A]'
              }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* DEMO WORKBENCH                                                       */}
      {/* ------------------------------------------------------------------ */}
      {activeSection === 'demo' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Left: controls */}
          <div className="space-y-4">
            {/* Notice */}
            <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-amber-300 text-[11px]">
              <FlaskConical className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>
                <strong>Controlled demo.</strong> Encrypts files with a real AES-256-GCM key.
                Does NOT decrypt ransomware samples. Does NOT represent real ransomware recovery.
              </span>
            </div>

            {/* Source mode toggle — only shown at idle */}
            {demoPhase === 'idle' && (
              <div className="flex gap-1 p-1 bg-[#111C2E] rounded-lg border border-[#24344D]">
                <button
                  onClick={() => setSourceMode('preset')}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-2 rounded text-[11px] font-medium transition ${
                    sourceMode === 'preset'
                      ? 'bg-[#16243A] text-[#F8FAFC] border border-[#3B82F6]/30'
                      : 'text-[#94A3B8] hover:text-[#F8FAFC]'
                  }`}
                >
                  <FlaskConical className="w-3 h-3" /> Preset Demo Files
                </button>
                <button
                  onClick={() => setSourceMode('custom')}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-2 rounded text-[11px] font-medium transition ${
                    sourceMode === 'custom'
                      ? 'bg-[#16243A] text-[#F8FAFC] border border-[#3B82F6]/30'
                      : 'text-[#94A3B8] hover:text-[#F8FAFC]'
                  }`}
                >
                  <Upload className="w-3 h-3" /> Upload Your Own File
                </button>
              </div>
            )}

            {/* Step 1A — Preset demo file selection */}
            {demoPhase === 'idle' && sourceMode === 'preset' && (
              <div className="space-y-3 p-4 rounded-lg bg-[#111C2E] border border-[#24344D]">
                <h3 className="text-xs font-semibold text-[#F8FAFC] uppercase tracking-wider">
                  Step 1 — Select &amp; Encrypt Demo File
                </h3>
                <select
                  value={selectedFile}
                  onChange={(e) => setSelectedFile(e.target.value)}
                  disabled={demoFiles.length === 0}
                  className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs font-mono focus:border-[#3B82F6] outline-none"
                >
                  {demoFiles.length === 0
                    ? <option>Loading...</option>
                    : demoFiles.map((f) => (
                      <option key={f.filename} value={f.filename}>
                        {f.filename}
                      </option>
                    ))}
                </select>
                {selectedFile && demoFiles.find(f => f.filename === selectedFile) && (
                  <p className="text-[11px] text-[#94A3B8]">
                    {demoFiles.find(f => f.filename === selectedFile)?.description}
                  </p>
                )}
                <button
                  onClick={handleEncryptPreset}
                  disabled={!selectedFile || demoBusy}
                  className="w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 bg-[#3B82F6] hover:bg-blue-600 text-white transition disabled:opacity-50"
                >
                  <Key className="w-3.5 h-3.5" />
                  Generate Key &amp; Encrypt
                </button>
              </div>
            )}

            {/* Step 1B — Custom file upload: encrypt or upload pre-existing .csde */}
            {demoPhase === 'idle' && sourceMode === 'custom' && (
              <div className="space-y-3 p-4 rounded-lg bg-[#111C2E] border border-[#24344D]">
                {/* Option A: encrypt a plain file */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-[#F8FAFC] uppercase tracking-wider">
                    Option A — Encrypt Your Own File
                  </h3>
                  <p className="text-[11px] text-[#94A3B8]">
                    Upload any benign file. The server encrypts it with AES-256-GCM and returns the key once.
                    The file is never executed.
                  </p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    onChange={(e) => {
                      const f = e.target.files?.[0] || null;
                      setCustomFile(f);
                      setCustomFileInfo(f ? `${f.name} (${(f.size / 1024).toFixed(1)} KB)` : '');
                    }}
                    className="hidden"
                    id="custom-file-input"
                  />
                  <label
                    htmlFor="custom-file-input"
                    className="flex items-center gap-2 w-full px-3 py-2 rounded-lg bg-[#0B1220] border border-[#24344D] border-dashed text-[#94A3B8] text-xs cursor-pointer hover:border-[#3B82F6] hover:text-[#3B82F6] transition"
                  >
                    <FolderOpen className="w-3.5 h-3.5 flex-shrink-0" />
                    {customFileInfo || 'Click to choose a file…'}
                  </label>
                  <button
                    onClick={handleEncryptCustomFile}
                    disabled={!customFile || demoBusy}
                    className="w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 bg-[#3B82F6] hover:bg-blue-600 text-white transition disabled:opacity-50"
                  >
                    <Key className="w-3.5 h-3.5" />
                    Generate Key &amp; Encrypt My File
                  </button>
                </div>

                <div className="border-t border-[#24344D] pt-3 space-y-2">
                  {/* Option B: upload pre-encrypted .csde */}
                  <h3 className="text-xs font-semibold text-[#F8FAFC] uppercase tracking-wider">
                    Option B — Upload a Pre-Existing .csde File
                  </h3>
                  <p className="text-[11px] text-[#94A3B8]">
                    Already have a <code className="font-mono">.csde</code> file from a previous session?
                    Upload it here, then enter your saved key to decrypt.
                  </p>
                  <input
                    ref={csdeInputRef}
                    type="file"
                    accept=".csde"
                    onChange={(e) => setUploadedCsdeFile(e.target.files?.[0] || null)}
                    className="hidden"
                    id="csde-file-input"
                  />
                  <label
                    htmlFor="csde-file-input"
                    className="flex items-center gap-2 w-full px-3 py-2 rounded-lg bg-[#0B1220] border border-[#24344D] border-dashed text-[#94A3B8] text-xs cursor-pointer hover:border-[#3B82F6] hover:text-[#3B82F6] transition"
                  >
                    <FolderOpen className="w-3.5 h-3.5 flex-shrink-0" />
                    {uploadedCsdeFile ? `${uploadedCsdeFile.name} (${(uploadedCsdeFile.size / 1024).toFixed(1)} KB)` : 'Click to choose a .csde file…'}
                  </label>
                  <button
                    onClick={handleUploadCsde}
                    disabled={!uploadedCsdeFile || demoBusy}
                    className="w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 bg-[#16243A] border border-[#24344D] hover:border-[#3B82F6] text-[#94A3B8] hover:text-[#F8FAFC] transition disabled:opacity-50"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    Upload &amp; Validate .csde
                  </button>
                </div>
              </div>
            )}

            {/* Step 2: key display + decrypt */}
            {(demoPhase === 'key_display' || demoPhase === 'decrypting' || demoPhase === 'done') && (
              <div className="space-y-3 p-4 rounded-lg bg-[#111C2E] border border-[#24344D]">
                <h3 className="text-xs font-semibold text-[#F8FAFC] uppercase tracking-wider">
                  Step 2 — Decrypt with Key
                </h3>

                {/* Show key display only when key was generated (not when .csde was uploaded) */}
                {demoKey && (
                  <div className="p-2.5 rounded-lg bg-amber-500/5 border border-amber-500/30 space-y-1">
                    <div className="text-[10px] text-amber-300 font-semibold flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Demo Key — Save now. NOT stored by server.
                    </div>
                    <div className="font-mono text-[10px] text-[#22C55E] break-all">{demoKey}</div>
                  </div>
                )}

                {/* When uploading .csde: no key was generated; prompt user to enter it */}
                {!demoKey && demoPhase !== 'idle' && (
                  <div className="p-2.5 rounded-lg bg-[#16243A] border border-[#24344D] text-[11px] text-[#94A3B8]">
                    Enter the key you saved when this file was originally encrypted.
                  </div>
                )}

                <div className="space-y-1">
                  <label className="text-[10px] text-[#94A3B8] uppercase tracking-wider font-medium">
                    Key (edit to test wrong-key rejection)
                  </label>
                  <input
                    type="text"
                    value={userKey}
                    onChange={(e) => setUserKey(e.target.value)}
                    disabled={demoBusy || demoPhase === 'done'}
                    placeholder="Paste your AES-256-GCM key (base64)…"
                    className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#3B82F6] font-mono text-xs focus:border-[#3B82F6] outline-none disabled:opacity-60"
                  />
                </div>

                {/* Download encrypted .csde — available after encrypt/upload */}
                {encryptedFilename && demoPhase !== 'done' && (
                  <button
                    onClick={handleDownloadEncrypted}
                    className="w-full py-2 rounded-lg font-medium text-xs flex items-center justify-center gap-2 border border-[#24344D] text-[#94A3B8] hover:text-[#F8FAFC] hover:border-[#3B82F6] transition"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download Encrypted File (.csde)
                  </button>
                )}

                {demoPhase !== 'done' && (
                  <button
                    onClick={handleDecrypt}
                    disabled={demoBusy || !userKey}
                    className={`w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 transition ${demoBusy
                        ? 'bg-[#16243A] text-[#94A3B8] cursor-not-allowed border border-[#24344D]'
                        : 'bg-[#3B82F6] hover:bg-blue-600 text-white'
                      }`}
                  >
                    {demoBusy
                      ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Processing...</>
                      : <><Unlock className="w-3.5 h-3.5" /> Run Decryption</>
                    }
                  </button>
                )}

                {demoPhase === 'done' && (
                  <button onClick={resetDemo} className="w-full py-2 rounded-lg text-xs border border-[#24344D] text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#16243A] transition flex items-center justify-center gap-2">
                    <RefreshCw className="w-3.5 h-3.5" /> New Demo
                  </button>
                )}
              </div>
            )}

            {/* Error */}
            {demoError && (
              <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/30 flex items-start gap-2 text-[11px] text-red-300">
                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                <span>{demoError}</span>
              </div>
            )}
          </div>

          {/* Right: log + result */}
          <div className="space-y-4">
            {/* Worker trace */}
            <div className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D]">
              <div className="flex items-center gap-1.5 text-[11px] text-[#3B82F6] font-medium pb-2 border-b border-[#24344D] mb-2">
                <Shield className="w-3.5 h-3.5" /> Cryptographic Worker Trace
              </div>
              <div className="h-48 overflow-y-auto space-y-0.5 text-[11px] font-mono">
                {demoLogs.length === 0
                  ? <div className="text-[#94A3B8]/50 italic text-center py-8">Awaiting operation...</div>
                  : demoLogs.map((log, i) => (
                    <div key={i} className={
                      log.includes('SUCCEEDED') || log.includes('✓') ? 'text-[#22C55E]'
                        : log.includes('ERROR') || log.includes('FAILED') ? 'text-red-400'
                          : log.includes('KEY') || log.includes('CRYPTO') ? 'text-[#3B82F6]'
                            : 'text-[#94A3B8]'
                    }>{log}</div>
                  ))
                }
              </div>
            </div>

            {/* Success result */}
            {demoSucceeded && demoJob && (
              <div className="p-4 rounded-lg bg-[#0B1220] border border-[#22C55E]/40 space-y-3">
                <div className="flex items-center gap-2 text-[#22C55E] text-xs font-medium">
                  <ShieldCheck className="w-4 h-4" /> Recovery Verified
                </div>
                <div className="space-y-1.5 text-[11px] font-mono">
                  <div className="flex justify-between">
                    <span className="text-[#94A3B8]">Status</span>
                    <StatusBadge status={demoJob.status} verified={demoJob.verified} />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94A3B8]">Verified</span>
                    <span className="text-[#22C55E]">{String(demoJob.verified)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94A3B8]">Output file</span>
                    <span className="text-[#F8FAFC] truncate max-w-[180px]">{demoJob.output_path}</span>
                  </div>
                  <div>
                    <div className="text-[#94A3B8] mb-0.5">Expected SHA-256</div>
                    <div className="text-[#3B82F6] break-all">{demoJob.plaintext_sha256}</div>
                  </div>
                  <div>
                    <div className="text-[#94A3B8] mb-0.5">Actual SHA-256</div>
                    <div className={demoJob.plaintext_sha256 === demoJob.output_sha256 ? 'text-[#22C55E] break-all' : 'text-red-400 break-all'}>
                      {demoJob.output_sha256}
                    </div>
                  </div>
                </div>
                {/* Download recovered file */}
                <button
                  onClick={handleDownloadRecovered}
                  className="w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 bg-[#22C55E]/10 border border-[#22C55E]/30 text-[#22C55E] hover:bg-[#22C55E]/20 transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download Recovered File
                </button>
              </div>
            )}

            {/* Failure result */}
            {demoPhase === 'done' && !demoSucceeded && demoJob && (
              <div className="p-4 rounded-lg bg-[#0B1220] border border-red-500/30 space-y-2">
                <div className="flex items-center gap-2 text-red-400 text-xs font-medium">
                  <XCircle className="w-4 h-4" />
                  <StatusBadge status={demoJob.status} verified={demoJob.verified} />
                </div>
                <p className="text-[11px] text-[#94A3B8]">
                  AES-GCM authentication rejected this key. No plaintext was released.
                  This is correct and expected when an incorrect key is provided.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* REGISTRY                                                             */}
      {/* ------------------------------------------------------------------ */}
      {activeSection === 'registry' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-[#94A3B8]">
              Registered decryptor adapters — status reflects the current server environment.
            </p>
            <button onClick={loadRegistry} disabled={registryLoading}
              className="text-xs text-[#3B82F6] hover:underline flex items-center gap-1">
              <RefreshCw className={`w-3 h-3 ${registryLoading ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>

          {adapters.length === 0 && !registryLoading && (
            <div className="p-8 text-center text-[#94A3B8] text-sm border border-[#24344D] rounded-lg">
              No adapters loaded.
            </div>
          )}

          {adapters.map((a) => (
            <div key={a.adapter_id} className="p-4 rounded-lg bg-[#111C2E] border border-[#24344D] space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <AdapterStatusDot status={a.status} />
                  <div>
                    <div className="text-sm font-medium text-[#F8FAFC]">{a.display_name}</div>
                    <div className="text-[11px] text-[#94A3B8]">{a.source} · ID: {a.adapter_id}</div>
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${a.status === 'AVAILABLE' ? 'text-[#22C55E] border-[#22C55E]/30 bg-[#22C55E]/5'
                    : a.status === 'REQUIRES_PREREQUISITES' ? 'text-amber-400 border-amber-400/30 bg-amber-400/5'
                      : 'text-[#94A3B8] border-[#24344D] bg-[#16243A]'
                  }`}>{a.status}</span>
              </div>

              <div className="grid grid-cols-2 gap-3 text-[11px]">
                <div>
                  <div className="text-[#94A3B8] mb-1 uppercase tracking-wider text-[10px]">Supported Families</div>
                  <div className="flex flex-wrap gap-1">
                    {a.supported_families.slice(0, 6).map((f) => (
                      <span key={f} className="px-1.5 py-0.5 rounded bg-[#16243A] border border-[#24344D] text-[#F8FAFC] font-mono">{f}</span>
                    ))}
                    {a.supported_families.length > 6 && (
                      <span className="text-[#94A3B8]">+{a.supported_families.length - 6} more</span>
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-[#94A3B8] mb-1 uppercase tracking-wider text-[10px]">Properties</div>
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-1.5">
                      {a.can_run_automatically
                        ? <CheckCircle className="w-3 h-3 text-[#22C55E]" />
                        : <XCircle className="w-3 h-3 text-[#94A3B8]" />}
                      <span className="text-[#94A3B8]">Automatic execution</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <AlertTriangle className="w-3 h-3 text-amber-400" />
                      <span className="text-[#94A3B8]">Requires explicit approval</span>
                    </div>
                  </div>
                </div>
              </div>

              {a.prerequisites.length > 0 && (
                <details className="text-[11px]">
                  <summary className="text-[#94A3B8] cursor-pointer hover:text-[#F8FAFC] select-none flex items-center gap-1">
                    <ChevronRight className="w-3 h-3" /> Prerequisites ({a.prerequisites.length})
                  </summary>
                  <ul className="mt-2 space-y-1 pl-4">
                    {a.prerequisites.map((p, i) => (
                      <li key={i} className="text-[#94A3B8] list-disc list-outside">{p}</li>
                    ))}
                  </ul>
                </details>
              )}

              {a.limitations.length > 0 && (
                <details className="text-[11px]">
                  <summary className="text-[#94A3B8] cursor-pointer hover:text-[#F8FAFC] select-none flex items-center gap-1">
                    <ChevronRight className="w-3 h-3" /> Limitations ({a.limitations.length})
                  </summary>
                  <ul className="mt-2 space-y-1 pl-4">
                    {a.limitations.map((l, i) => (
                      <li key={i} className="text-[#94A3B8] list-disc list-outside">{l}</li>
                    ))}
                  </ul>
                </details>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* JOB HISTORY                                                          */}
      {/* ------------------------------------------------------------------ */}
      {activeSection === 'jobs' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-[#94A3B8]">
              In-memory job history (cleared on server restart). No key material stored.
            </p>
            <button onClick={loadJobs} disabled={jobsLoading}
              className="text-xs text-[#3B82F6] hover:underline flex items-center gap-1">
              <RefreshCw className={`w-3 h-3 ${jobsLoading ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>

          {jobs.length === 0 && !jobsLoading && (
            <div className="p-8 text-center text-[#94A3B8] text-sm border border-[#24344D] rounded-lg border-dashed">
              No jobs yet. Run a demo to see job history here.
            </div>
          )}

          {jobs.slice().reverse().map((job) => (
            <div key={job.job_id} className="p-4 rounded-lg bg-[#111C2E] border border-[#24344D] space-y-2 text-[11px] font-mono">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <StatusBadge status={job.status} verified={job.verified} />
                  <span className="text-[#94A3B8]">{job.job_type}</span>
                </div>
                <span className="text-[#94A3B8] text-[10px]">
                  {job.completed_at ? new Date(job.completed_at).toLocaleTimeString() : 'In progress'}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                <div><span className="text-[#94A3B8]">Job ID: </span><span className="text-[#F8FAFC]">{job.job_id.slice(0, 8)}...</span></div>
                <div><span className="text-[#94A3B8]">Verified: </span><span className={job.verified ? 'text-[#22C55E]' : 'text-[#94A3B8]'}>{String(job.verified)}</span></div>
                <div className="col-span-2"><span className="text-[#94A3B8]">Input: </span><span className="text-[#F8FAFC]">{job.input_file || '—'}</span></div>
                <div className="col-span-2"><span className="text-[#94A3B8]">Output: </span><span className="text-[#F8FAFC]">{job.output_path || '—'}</span></div>
                {job.error_message && (
                  <div className="col-span-2 text-red-400"><span className="text-[#94A3B8]">Error: </span>{job.error_message}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
