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
} from 'lucide-react';
import confetti from 'canvas-confetti';

interface DecryptionWorkbenchModalProps {
  sample: SampleAnalysis;
  isOpen: boolean;
  onClose: () => void;
}

export const DecryptionWorkbenchModal: React.FC<DecryptionWorkbenchModalProps> = ({
  sample,
  isOpen,
  onClose
}) => {
  const [selectedFileToDecrypt, setSelectedFileToDecrypt] = useState('Confidential_Financials_Q3.docx.HLJkNskO6');
  const [customKey, setCustomKey] = useState(sample.decryptionKeyCandidate || '0x8F92_A140_99CE_10AB_4420_88FA_1120_CDE5');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [decryptionLogs, setDecryptionLogs] = useState<string[]>([]);
  const [decryptedPayload, setDecryptedPayload] = useState<string | null>(null);

  // Update key when sample changes
  useEffect(() => {
    if (sample.decryptionKeyCandidate) {
      setCustomKey(sample.decryptionKeyCandidate);
    }
  }, [sample]);

  if (!isOpen) return null;

  const handleStartDecryption = () => {
    setIsDecrypting(true);
    setProgress(0);
    setDecryptedPayload(null);
    setDecryptionLogs([
      `[00:00.010] [INIT] Loading target encrypted payload: "${selectedFileToDecrypt}"`,
      `[00:00.080] [KEY_LOAD] Ingesting candidate key: ${customKey}`,
      `[00:00.150] [IV_EXTRACT] Extracting initial 16-byte initialization vector from file header offset 0x00...`
    ]);

    // Step progression
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + 25;
      });
    }, 400);

    setTimeout(() => {
      setDecryptionLogs((prev) => [
        ...prev,
        `[00:00.600] [CIPHER] Applying AES-256-CBC inverse substitution-permutation network...`,
        `[00:00.950] [STREAM] Decrypting ciphertext block 0 to 4096...`,
        `[00:01.300] [INTEGRITY] Validating PKCS#7 padding bytes: 0x08 0x08 0x08... (VALID ✓)`
      ]);
    }, 800);

    setTimeout(() => {
      setDecryptionLogs((prev) => [
        ...prev,
        `[00:01.600] [MAGIC_CHECK] Discovered standard DOCX Zip Magic Header: [50 4B 03 04]`,
        `[00:01.800] [SUCCESS] Target file restored successfully! 100% data integrity verified.`
      ]);
      setDecryptedPayload(
        `CONFIDENTIAL EXECUTIVE BRIEFING - Q3\n` +
        `--------------------------------------------------\n` +
        `Document Status: RESTORED via CyberShield Decryptor Engine\n` +
        `Ransomware Defeated: ${sample.ransomwareFamily}\n` +
        `Derived Reconstructed Key: ${customKey}\n\n` +
        `Quarterly Operating Revenue: $14,250,000\n` +
        `Enterprise Security Budget: $2,800,000\n` +
        `Infrastructure Risk Status: MITIGATED\n` +
        `\nIntegrity Signature: SHA-256 Validated (Zero Data Loss)`
      );
      setIsDecrypting(false);

      // Trigger confetti
      confetti({
        particleCount: 60,
        spread: 60,
        origin: { y: 0.6 }
      });
    }, 2000);
  };

  const downloadDecryptedFile = () => {
    const blob = new Blob([decryptedPayload || 'Decrypted by CyberShield'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedFileToDecrypt.replace(/\.[^/.]+$/, '');
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#111C2E] border border-[#24344D] rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Modal Header */}
        <div className="p-4 border-b border-[#24344D] flex items-center justify-between bg-[#16243A]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-[#3B82F6]/10 text-[#3B82F6] border border-[#3B82F6]/20">
              <Key className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-[#F8FAFC]">
                Decryption Workbench
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

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">
          {/* Target File Selection */}
          <div className="space-y-1">
            <label className="text-[#94A3B8] text-[11px] font-medium uppercase tracking-wider block font-sans">
              1. Target Encrypted File
            </label>
            <select
              value={selectedFileToDecrypt}
              onChange={(e) => setSelectedFileToDecrypt(e.target.value)}
              className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs font-mono focus:border-[#3B82F6] outline-none cursor-pointer"
            >
              <option value="Confidential_Financials_Q3.docx.HLJkNskO6">
                Confidential_Financials_Q3.docx.HLJkNskO6 (LockBit)
              </option>
              <option value="Enterprise_Database_Backup.sql.WNCRY">
                Enterprise_Database_Backup.sql.WNCRY (WannaCry)
              </option>
              <option value="Customer_Vault_Credentials.xlsx.locked">
                Customer_Vault_Credentials.xlsx.locked (Babuk)
              </option>
            </select>
          </div>

          {/* Master Key Input */}
          <div className="space-y-1">
            <div className="flex items-center justify-between font-sans">
              <label className="text-[#94A3B8] text-[11px] font-medium uppercase tracking-wider">
                2. Recovered Master Key / Seed
              </label>
              <span className="text-[11px] text-[#22C55E] font-medium">Reconstructed ✓</span>
            </div>
            <input
              type="text"
              value={customKey}
              onChange={(e) => setCustomKey(e.target.value)}
              className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#3B82F6] font-mono text-xs focus:border-[#3B82F6] outline-none"
              placeholder="0x..."
            />
          </div>

          {/* Action Trigger */}
          <button
            onClick={handleStartDecryption}
            disabled={isDecrypting}
            className={`w-full py-2.5 rounded-lg font-medium text-xs flex items-center justify-center gap-2 transition ${
              isDecrypting
                ? 'bg-[#16243A] text-[#94A3B8] cursor-not-allowed border border-[#24344D]'
                : 'bg-[#3B82F6] hover:bg-blue-600 text-white'
            }`}
          >
            {isDecrypting ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#3B82F6]" />
                <span>Reconstructing Stream ({progress}%)...</span>
              </>
            ) : (
              <>
                <Unlock className="w-3.5 h-3.5" />
                <span>Execute Cryptographic Recovery</span>
              </>
            )}
          </button>

          {/* Decryption Log Console */}
          <div className="p-3 rounded-lg bg-[#0B1220] border border-[#24344D] space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-[#94A3B8] pb-1 border-b border-[#24344D]">
              <span className="flex items-center gap-1.5 text-[#3B82F6] font-medium">
                <Terminal className="w-3.5 h-3.5" /> Decryptor Worker Trace
              </span>
              <span className="text-[10px] text-[#22C55E]">Hardware Acceleration (AES-NI)</span>
            </div>
            <div className="h-24 overflow-y-auto space-y-1 text-[11px] text-[#F8FAFC] font-mono">
              {decryptionLogs.length === 0 ? (
                <div className="text-[#94A3B8]/60 italic text-center py-3">
                  Ready to execute decryption stream...
                </div>
              ) : (
                decryptionLogs.map((log, i) => (
                  <div key={i} className={log.includes('SUCCESS') ? 'text-[#22C55E] font-medium' : 'text-[#94A3B8]'}>
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Recovered Content Preview */}
          {decryptedPayload && (
            <div className="p-3.5 rounded-lg bg-[#0B1220] border border-[#22C55E]/40 space-y-2.5 animate-in fade-in">
              <div className="flex items-center justify-between font-sans">
                <span className="text-xs font-medium text-[#22C55E] flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5" /> Recovered Plaintext Preview
                </span>
                <button
                  onClick={downloadDecryptedFile}
                  className="px-2.5 py-1 rounded bg-[#22C55E] hover:bg-green-600 text-slate-950 font-medium text-[11px] flex items-center gap-1 transition"
                >
                  <Download className="w-3 h-3" />
                  <span>Download File</span>
                </button>
              </div>

              <pre className="p-2.5 rounded bg-[#111C2E] border border-[#24344D] text-[#F8FAFC] text-[11px] font-mono whitespace-pre-wrap max-h-32 overflow-y-auto">
                {decryptedPayload}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

