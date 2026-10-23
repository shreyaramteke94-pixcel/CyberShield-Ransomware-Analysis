import { EligibilityResult, DecryptorInfo } from '../types';

const API_BASE = 'http://localhost:8000';

/**
 * Checks real ransomware recovery eligibility for an uploaded and analysed sample.
 * Calls backend POST /api/v1/decryption/{sample_id}/eligibility.
 * Returns honest status (DECRYPTOR_UNAVAILABLE, FAMILY_UNKNOWN, etc.) with evidence and limitations.
 */
export async function fetchRecoveryEligibility(sampleId: string): Promise<EligibilityResult> {
  const resp = await fetch(`${API_BASE}/api/v1/decryption/${encodeURIComponent(sampleId)}/eligibility`, {
    method: 'POST',
  });

  if (!resp.ok) {
    const errText = await resp.text();
    let detail = errText;
    try {
      const parsed = JSON.parse(errText);
      if (parsed.detail) detail = parsed.detail;
    } catch {
      // keep raw
    }
    throw new Error(detail || `Eligibility check failed: HTTP ${resp.status}`);
  }

  return resp.json();
}

/**
 * Fetches the registered decryptor adapters from the backend registry.
 */
export async function fetchDecryptorRegistry(): Promise<{
  adapters: DecryptorInfo[];
  total: number;
  available: number;
}> {
  const resp = await fetch(`${API_BASE}/api/v1/decryption/registry`);
  if (!resp.ok) {
    throw new Error(`Registry fetch failed: HTTP ${resp.status}`);
  }
  return resp.json();
}
