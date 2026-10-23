# CyberShield SQLite Persistence Architecture & Operational Guide

This document describes the SQLite persistence layer, schema models, job lifecycle transitions, security controls, and operational backup/recovery procedures for the CyberShield Ransomware Analysis and Recovery platform.

---

## 1. Database Location & Configuration

- **Database Engine**: SQLite 3 via SQLAlchemy 2.0 ORM (`sqlite:///./cybershield.db`).
- **File Location**: `backend/cybershield.db` (relative to `backend/`).
- **Configuration Parameter**: `DATABASE_URL=sqlite:///./cybershield.db` in `backend/.env` (parsed in `app/config.py`).
- **Concurrency & Thread Safety**: Initialized with `connect_args={"check_same_thread": False}` in `app/database/database.py`, enabling safe concurrent read/write across FastAPI worker threads.
- **Automatic Initialization**: On backend startup, `Base.metadata.create_all(bind=engine)` in `app/main.py` automatically initializes all required tables if they do not yet exist.

---

## 2. Relational Schema & Models

The database contains four primary models registered with SQLAlchemy `Base`:

### A. `samples` (`Sample` in `app/models/sample.py`)
Tracks uploaded suspicious binaries and documents:
- `id`: UUID string (primary key, 36 chars)
- `original_filename`: User's original uploaded filename
- `stored_filename`: Cryptographically randomized filename on disk
- `file_extension`: File extension (e.g. `.exe`, `.bin`)
- `file_size`: Integer file size in bytes
- `sha256`: SHA-256 hash of uploaded file
- `status`: Lifecycle status (`uploaded`, `analyzed`, etc.)
- `uploaded_at`: UTC timestamp
- **Relationships**:
  - `analysis`: One-to-one relationship with `Analysis` (`cascade="all, delete-orphan"`).
  - `sandbox_jobs`: One-to-many relationship with `SandboxJob` (`cascade="all, delete-orphan"`).
  - `decryption_jobs`: One-to-many relationship with `DecryptionJob` (`cascade="all, delete-orphan"`).

### B. `analysis` (`Analysis` in `app/models/analysis.py`)
Stores static inspection, heuristic, YARA, and ML risk classification results:
- `id`: UUID string (primary key)
- `sample_id`: Foreign key referencing `samples.id` (`ondelete="CASCADE"`)
- `risk_score`: Heuristic threat score (0-100)
- `risk_level`: Severity verdict (`CLEAN`, `SUSPICIOUS`, `HIGH_RISK`)
- `static_analysis`: JSON blob containing headers, sections, entropy, and imports
- `yara_matches`: JSON array of matching YARA signature rules
- `ml_classification`: JSON blob containing random forest model prediction and confidence
- `created_at`: UTC timestamp

### C. `sandbox_jobs` (`SandboxJob` in `app/models/sandbox_job.py`)
Persists dynamic sandbox execution jobs, container security assertions, and runtime telemetry:
- `id`: UUID string (primary key, indexed)
- `sample_id`: Foreign key referencing `samples.id` (`ondelete="SET NULL"`, nullable, indexed)
- `filename`: Target sample filename
- `status`: Execution state (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `TIMED_OUT`, `UNAVAILABLE`)
- `created_at`: ISO-8601 UTC creation timestamp
- `completed_at`: ISO-8601 UTC completion timestamp (null while running)
- `operations_run`: JSON array of setup and containment steps
- `error_message`: Text explaining execution failure or timeout (or null on success)
- `process_tree`: JSON array of processes spawned inside container
- `network_beacons`: JSON array of intercepted outbound network attempts
- `runtime_events`: JSON array of behavioral telemetry events
- `security_verifications`: JSON map of defensive container controls enforced
- `execution_summary`: Text summarizing analysis findings

### D. `decryption_jobs` (`DecryptionJob` in `app/models/decryption_job.py`)
Persists ransomware recovery attempts, cryptographic verification, and artifact pointers:
- `id`: UUID string (primary key, indexed)
- `sample_id`: Foreign key referencing `samples.id` (`ondelete="SET NULL"`, nullable, indexed)
- `job_type`: Job class (`DEMO` or `REAL`, default `DEMO`)
- `status`: Recovery state (`READY_FOR_RECOVERY`, `RECOVERY_IN_PROGRESS`, `RECOVERY_SUCCEEDED`, `RECOVERY_FAILED`, `OUTPUT_VERIFICATION_FAILED`)
- `input_file`: Basename of encrypted input file
- `output_path`: Safe server file path of recovered plaintext
- `plaintext_sha256`: Expected SHA-256 hash of authentic plaintext
- `output_sha256`: Computed SHA-256 hash of recovered plaintext
- `verified`: Boolean indicating byte-for-byte SHA-256 match
- `error_message`: Safe error explanation (sanitized against secret leakage)
- `created_at`: ISO-8601 UTC creation timestamp
- `completed_at`: ISO-8601 UTC completion timestamp

---

## 3. Cryptographic Security & Zero-Secret Policy

To maintain strict operational security and defense-in-depth:
1. **Zero Key Storage**:
   - The `decryption_jobs` table contains **no key column**.
   - Neither the AES-256-GCM symmetric key nor the Base64 representation is persisted to SQLite or written to application logs.
   - The user or analyst holds the decryption key; it is supplied ephemerally during recovery job initiation and discarded from memory immediately after execution.
2. **Path Containment & Traversal Defense**:
   - Recovered plaintext outputs are confined strictly within `recovery-output/`.
   - Before serving any recovered file via `GET /api/v1/decryption/demo/jobs/{job_id}/download`, `output_path.relative_to(approved_dir)` verifies path containment. Traversal attempts (`../`, `..\`) are rejected with HTTP 400.
3. **Download Authorization & Integrity Verification**:
   - Downloads are only permitted if `status == "RECOVERY_SUCCEEDED"` AND `verified == True`.
   - Attempting to download unverified or failed outputs is blocked with HTTP 400.
   - If a recovered file is missing from disk, the endpoint responds with HTTP 404 rather than leaking internal paths.

---

## 4. Job Lifecycle & Restart Persistence Behavior

Both `SandboxManager` (`app/sandbox/manager.py`) and `DecryptionOrchestrator` (`app/decryption/orchestrator.py`) implement a tiered cache-and-database architecture:
- **Write-Through Persistence**: Whenever a job transitions state (`create_job`, `RUNNING`, `COMPLETED`, `TIMED_OUT`, `UNAVAILABLE`, `FAILED`), `_persist_job()` immediately synchronizes the record to the SQLite database.
- **Fail-Safe Retrieval Across Restarts**:
  - `get_job(job_id)` checks the active in-memory cache first. If the cache is empty (such as after a FastAPI restart), it queries the database through the repository and re-populates the cache.
  - `list_jobs()` queries the database ordered by `created_at DESC` to ensure historical jobs created prior to server restart remain fully accessible.
- **Database Failure Fallback**: If SQLite encounters a lock or write error, `_persist_job()` logs an error and safely continues using the in-memory store so running operations are never abruptly crashed.

---

## 5. Backup & Maintenance Procedures

### Online Backup (Hot Backup)
To create a safe snapshot while the backend is running:
```powershell
sqlite3 backend/cybershield.db ".backup 'backend/cybershield_backup.db'"
```

### Cold Backup
When the backend service is stopped:
```powershell
Copy-Item backend/cybershield.db backend/cybershield_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').db
```

### Integrity Verification
To verify the integrity of the database file:
```powershell
sqlite3 backend/cybershield.db "PRAGMA integrity_check;"
```
Expected output: `ok`.
