import React, { useState } from 'react';
import { 
  Cpu, 
  Bell, 
  Save, 
  Check, 
} from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [sandboxTimeout, setSandboxTimeout] = useState('60');
  const [mlModel, setMlModel] = useState('DeepMalwareNet-v4.8');
  const [autoDecrypt, setAutoDecrypt] = useState(true);
  const [antiVmBypass, setAntiVmBypass] = useState(true);
  const [webhookUrl, setWebhookUrl] = useState('https://hooks.slack.com/services/T00/B00/XXXX');
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-6 max-w-3xl pb-12" id="cybershield-settings-page">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-[#F8FAFC]">
          Platform Settings
        </h1>
        <p className="text-xs text-[#94A3B8] mt-0.5">
          Malware detonation thresholds, heuristic models, and SIEM alerting webhooks
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-5">
        {/* Detonation Engine Settings */}
        <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4 text-xs">
          <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#3B82F6]" />
            <span>Detonation Sandbox Parameters</span>
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="text-[#94A3B8] block text-[11px] font-medium">Detonation Timeout</label>
              <select
                value={sandboxTimeout}
                onChange={(e) => setSandboxTimeout(e.target.value)}
                className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#F8FAFC] focus:border-[#3B82F6] outline-none"
              >
                <option value="30">30 seconds (Fast Triage)</option>
                <option value="60">60 seconds (Standard Analysis)</option>
                <option value="120">120 seconds (Deep Sleep-Bypass)</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-[#94A3B8] block text-[11px] font-medium">ML Classification Model</label>
              <select
                value={mlModel}
                onChange={(e) => setMlModel(e.target.value)}
                className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#F8FAFC] focus:border-[#3B82F6] outline-none"
              >
                <option value="DeepMalwareNet-v4.8">DeepMalwareNet v4.8 (Transformer + XGB)</option>
                <option value="CyberShield-Neural-v5.0-Beta">CyberShield Neural v5.0 (Beta)</option>
                <option value="Static-Heuristics-Only">Static Rules Only</option>
              </select>
            </div>
          </div>

          <div className="pt-3 border-t border-[#24344D] space-y-3">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={autoDecrypt}
                onChange={(e) => setAutoDecrypt(e.target.checked)}
                className="w-4 h-4 rounded text-[#3B82F6] bg-[#0B1220] border-[#24344D] mt-0.5"
              />
              <div>
                <div className="text-xs font-medium text-[#F8FAFC]">Autonomous Cryptographic Key Extraction</div>
                <div className="text-[11px] text-[#94A3B8]">Attempt seed factorization and key derivation automatically upon ransomware detection</div>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={antiVmBypass}
                onChange={(e) => setAntiVmBypass(e.target.checked)}
                className="w-4 h-4 rounded text-[#3B82F6] bg-[#0B1220] border-[#24344D] mt-0.5"
              />
              <div>
                <div className="text-xs font-medium text-[#F8FAFC]">Hardware CPUID &amp; Anti-VM Masking</div>
                <div className="text-[11px] text-[#94A3B8]">Obfuscate virtualization signatures to prevent evasion techniques</div>
              </div>
            </label>
          </div>
        </div>

        {/* Integration Webhooks */}
        <div className="p-5 rounded-xl bg-[#111C2E] border border-[#24344D] space-y-4 text-xs">
          <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2">
            <Bell className="w-4 h-4 text-[#3B82F6]" />
            <span>Alerting &amp; Webhooks</span>
          </h2>

          <div className="space-y-1">
            <label className="text-[#94A3B8] block text-[11px] font-medium">Incident Alert Webhook (SIEM / Slack / Teams)</label>
            <input
              type="text"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              className="w-full bg-[#0B1220] border border-[#24344D] rounded-lg px-3 py-2 text-[#F8FAFC] focus:border-[#3B82F6] outline-none font-mono text-xs"
            />
          </div>
        </div>

        {/* Submit */}
        <div className="flex items-center justify-between pt-1">
          <span className="text-xs text-[#94A3B8]">CyberShield Enterprise v4.2</span>
          <button
            type="submit"
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-xs transition"
          >
            {saved ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}
            <span>{saved ? 'Saved' : 'Save Changes'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};

