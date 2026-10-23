import {
  SandboxDetectorResponse,
  SandboxJobRequest,
  SandboxJobResponse,
} from '../types';

const API_BASE = 'http://localhost:8000';

/**
 * Interrogates backend for Docker CLI, daemon, and verified sandbox image readiness.
 */
export async function fetchSandboxStatus(): Promise<SandboxDetectorResponse> {
  const resp = await fetch(`${API_BASE}/api/v1/sandbox/status`);
  if (!resp.ok) {
    throw new Error(`Sandbox status check failed: HTTP ${resp.status}`);
  }
  return resp.json();
}

/**
 * Submits an uploaded sample for containerized dynamic analysis.
 * Requires explicit confirm_dynamic_execution: true.
 */
export async function submitSandboxJob(
  payload: SandboxJobRequest
): Promise<SandboxJobResponse> {
  const resp = await fetch(`${API_BASE}/api/v1/sandbox/jobs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    let detail = errText;
    try {
      const parsed = JSON.parse(errText);
      if (parsed.detail) detail = parsed.detail;
    } catch {
      // keep raw errText
    }
    throw new Error(detail || `Sandbox job submission failed: HTTP ${resp.status}`);
  }
  return resp.json();
}

/**
 * Fetches status, diagnostics, and telemetry for a specific sandbox job.
 */
export async function fetchSandboxJob(jobId: string): Promise<SandboxJobResponse> {
  const resp = await fetch(`${API_BASE}/api/v1/sandbox/jobs/${encodeURIComponent(jobId)}`);
  if (!resp.ok) {
    throw new Error(`Sandbox job lookup failed: HTTP ${resp.status}`);
  }
  return resp.json();
}

/**
 * Lists all sandbox execution jobs submitted during this application session.
 */
export async function fetchSandboxJobs(): Promise<SandboxJobResponse[]> {
  const resp = await fetch(`${API_BASE}/api/v1/sandbox/jobs`);
  if (!resp.ok) {
    throw new Error(`Sandbox jobs list failed: HTTP ${resp.status}`);
  }
  return resp.json();
}
