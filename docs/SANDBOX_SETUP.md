# CyberShield Sandbox Subsystem — Setup & Verification Guide

This guide details how to build, verify, and operate the isolated Docker sandbox subsystem for CyberShield defensive malware analysis.

---

## 1. Architecture & Security Model

The CyberShield dynamic analysis sandbox executes suspicious samples within an isolated Linux container using Docker Desktop on Windows (WSL2 engine).

### Enforced Security Boundaries

| Control | Flag / Parameter | Defensive Guarantee |
| :--- | :--- | :--- |
| **Network Isolation** | `--network none` | Completely air-gapped; blocks outbound C2 beacons and DNS exfiltration. |
| **Execution Identity** | `--user 1000:1000` | Unprivileged non-root user; root execution inside the container is strictly denied. |
| **Root Filesystem** | `--read-only` | Prevents persistence, payload drops, or modifications to container system binaries. |
| **Sample Mount** | `-v <sample>:/sandbox/sample:ro` | Sample is mounted strictly read-only; container cannot alter or delete target binary. |
| **Output Mount** | `-v <temp_dir>:/sandbox/output:rw` | Ephemeral, isolated temporary directory for `telemetry.json` retrieval. Cleaned up immediately. |
| **Temporary Workspace** | `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | In-memory scratch space with `noexec` to prevent payload staging in `/tmp`. |
| **Capabilities** | `--cap-drop ALL` | Strips all Linux capabilities (cannot mount, ptrace, or configure network devices). |
| **Privilege Escalation**| `--security-opt no-new-privileges:true` | Prevents `setuid` binaries from escalating privileges. |
| **Resource Limits** | `--cpus 1.0 --memory 512m --pids-limit 64` | Restricts CPU, RAM, and prevents fork bombs / denial of service. |
| **Execution Timeout** | `timeout_seconds` (default: 60s) | Subprocess execution terminates and runs `docker rm -f` if exceeded. |
| **Fail-Closed Policy** | Internal checks | If Docker or the image is absent, dynamic execution is refused with `UNAVAILABLE`. **Host fallback execution is strictly prohibited.** |

---

## 2. Prerequisites

1. **Docker Desktop for Windows**:
   - Install Docker Desktop with the WSL2 backend enabled.
   - Start Docker Desktop and verify the daemon is running:
     ```powershell
     docker info
     ```

2. **Python Environment**:
   - Python 3.12 virtual environment in `venv/`.

3. **Node.js Environment**:
   - Node.js 18+ for building the React/TypeScript frontend.

---

## 3. Building the Sandbox Container Image

From the project root (`CyberShield-Ransomware-Analysis`), run the following PowerShell command:

```powershell
# Build and load the isolated sandbox image into the local Docker daemon
docker build --load -t cybershield/analysis-sandbox:latest docker/sandbox
```

Verify that the image is registered and inspect its configuration:

```powershell
docker image inspect cybershield/analysis-sandbox:latest --format "{{.Id}} User={{.Config.User}} Entrypoint={{.Config.Entrypoint}}"
```

Expected output:
```
sha256:... User=1000:1000 Entrypoint=[python3 /sandbox/entrypoint.py]
```

---

## 4. Verifying End-to-End Dynamic Analysis

### A. Run Sandbox Diagnostics via Python

```powershell
# From project root
.\venv\Scripts\python.exe -c "import json; from backend.app.sandbox.detector import get_sandbox_status; print(json.dumps(get_sandbox_status().model_dump(), indent=2))"
```

Expected response status:
- `docker_cli_available: true`
- `docker_daemon_reachable: true`
- `sandbox_image_available: true`
- `dynamic_analysis_ready: true`
- `sandbox_status: "AVAILABLE"`

### B. Run Backend Test Suite

```powershell
cd backend
..\venv\Scripts\python.exe -m pytest tests/test_sandbox.py -v
```

All 14 sandbox tests should pass, including:
- Docker detector reporting
- Security policies dictionary checks
- Fail-closed behavior when Docker is absent
- Real container execution with synthetic sample
- Timeout enforcement and container cleanup
- Path traversal and containment boundary validation

### C. Run Full Test Suite

```powershell
# From backend directory
..\venv\Scripts\python.exe -m pytest tests/ app/decryption/tests/
```

Expected result: **155 passed**.

### D. Build Frontend

```powershell
cd ..\frontend
npm run build
```

Expected result: Production build succeeds with 0 TypeScript errors.

---

## 5. Safe Synthetic Verification

To verify container execution without executing untrusted binaries, submit a harmless text or benign binary file through the frontend or API:

```powershell
# 1. Upload harmless synthetic file
$upload = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/upload/" -Method Post -Form @{
    file = Get-Item -Path ".\backend\uploads\yara_test.txt"
}
$sampleId = $upload.id

# 2. Submit for dynamic sandbox analysis with opt-in confirmation
$job = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/sandbox/jobs" -Method Post -ContentType "application/json" -Body (@{
    sample_id = $sampleId
    confirm_dynamic_execution = $true
    timeout_seconds = 60
} | ConvertTo-Json)

# 3. View job result
$job | ConvertTo-Json -Depth 5
```

---

## 6. Security Limitations & Operational Boundaries

1. **Static/Defensive Container Inspection**:
   The current container entrypoint performs safe, non-destructive file inspection (SHA-256/MD5 hashing, Shannon entropy calculation, magic byte detection, string extraction, and containment boundary checks). It does not trigger arbitrary Windows PE execution (`.exe` malware) because the runner is an Alpine Linux container.
2. **Container Escapes**:
   Containers provide process and namespace isolation but share the host Linux kernel (WSL2 VM). They do not offer the full hardware virtualization isolation of a dedicated type-1 hypervisor (e.g. ESXi/Xen) or hypervisor-isolated sandbox (e.g. Cuckoo Sandbox with Windows VMs).
3. **Opt-in Authorization**:
   Dynamic detonation requires explicit authorization (`confirm_dynamic_execution: true`). Without this flag, requests are immediately rejected with HTTP 400.
