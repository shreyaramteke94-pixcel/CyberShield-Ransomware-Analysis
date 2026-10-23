"""
In-memory recovery job orchestrator for the CyberShield Decryption Engine.

Design
------
Jobs are stored in a module-level dict protected by a threading.Lock.
This is sufficient for a single-process FastAPI/uvicorn deployment.

A job is never deleted from the store so that job history is available
for the duration of the server process.  Jobs are not persisted to disk
(per Stage B requirements — no DB model).

Recovery status values
----------------------
  READY_FOR_RECOVERY      – Job accepted; queued (not yet running)
  RECOVERY_IN_PROGRESS    – Decryption is executing
  RECOVERY_SUCCEEDED      – Decryption completed AND integrity verified
  RECOVERY_FAILED         – Decryption raised an exception
  OUTPUT_VERIFICATION_FAILED – Decryption succeeded but verification failed

Rule: RECOVERY_SUCCEEDED is set ONLY when:
  1. demo_crypto.decrypt() returned plaintext without raising.
  2. The output was written to the designated output path.
  3. verification.verify_demo_output() returned True.

Path-safety rules
-----------------
  - All resolved paths are checked against their approved base directory.
  - demo_filename and encrypted_filename may only be simple basenames.
  - Symlinks are resolved before the containment check.
  - Output filenames are derived from job_id, not from user input.
"""

import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4
import base64

from sqlalchemy.orm import Session

from app.decryption import demo_crypto
from app.decryption import verification
from app.decryption.exceptions import (
    DemoFileNotFoundError,
    EncryptedFileNotFoundError,
    FileSizeLimitError,
    JobAlreadyRunningError,
    JobNotFoundError,
    PathTraversalError,
    TamperedCiphertextError,
    InvalidFormatError,
    InvalidKeyError,
    UnsupportedVersionError,
    IntegrityError,
)

logger = logging.getLogger(__name__)

# Maximum demo file size: 50 MB (matches existing MAX_FILE_SIZE convention)
_DEMO_MAX_FILE_SIZE: int = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

# Track which encrypted files currently have an IN_PROGRESS job.
# Key: encrypted_filename  Value: job_id
_active_encrypted: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Database persistence helper
# ---------------------------------------------------------------------------


def _persist_job(job: dict, db: Optional[Session] = None) -> None:
    """Persist or update decryption job in SQLite database safely."""
    from app.database.database import SessionLocal
    from app.repositories.decryption_job_repository import DecryptionJobRepository

    if db is not None:
        try:
            DecryptionJobRepository.create_or_update(db, job)
        except Exception as e:
            logger.error("Failed to persist decryption job %s with db session: %s", job.get("job_id"), e)
        return

    try:
        session = SessionLocal()
        try:
            DecryptionJobRepository.create_or_update(session, job)
        finally:
            session.close()
    except Exception as e:
        logger.error("Failed to persist decryption job %s with SessionLocal: %s", job.get("job_id"), e)


# ---------------------------------------------------------------------------
# Recovery status constants
# ---------------------------------------------------------------------------


class RecoveryStatus:
    READY_FOR_RECOVERY = "READY_FOR_RECOVERY"
    RECOVERY_IN_PROGRESS = "RECOVERY_IN_PROGRESS"
    RECOVERY_SUCCEEDED = "RECOVERY_SUCCEEDED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    OUTPUT_VERIFICATION_FAILED = "OUTPUT_VERIFICATION_FAILED"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def list_demo_input_files(demo_dir: Path) -> list[dict]:
    """
    Return metadata for all plaintext demo files in *demo_dir*.

    Only regular files directly inside *demo_dir* (not subdirectories)
    are listed.

    Returns
    -------
    list of dicts with keys: filename, size_bytes, description
    """
    demo_dir = demo_dir.resolve()
    if not demo_dir.is_dir():
        return []

    _DESCRIPTIONS = {
        "quarterly_report_demo.txt": (
            "Simulated quarterly business report — plain text format"
        ),
        "client_data_sample_demo.csv": (
            "Simulated client data extract — CSV format"
        ),
        "configuration_backup_demo.json": (
            "Simulated application configuration backup — JSON format"
        ),
    }

    result = []
    for entry in sorted(demo_dir.iterdir()):
        if entry.is_file() and entry.name != ".gitkeep":
            resolved = entry.resolve()
            # Containment check
            if not str(resolved).startswith(str(demo_dir)):
                continue
            result.append(
                {
                    "filename": entry.name,
                    "size_bytes": entry.stat().st_size,
                    "description": _DESCRIPTIONS.get(
                        entry.name, "Controlled demo file"
                    ),
                }
            )
    return result


def encrypt_demo_file(
    demo_dir: Path,
    filename: str,
    encrypted_dir: Path,
) -> dict:
    """
    Encrypt a plaintext demo file with a freshly generated AES-256-GCM key.

    The encrypted blob is written to *encrypted_dir*.
    The key is returned in the result dict and is NOT stored server-side.

    Parameters
    ----------
    demo_dir : Path
        Directory containing plaintext demo files.
    filename : str
        Basename of the plaintext file to encrypt.
    encrypted_dir : Path
        Directory where the encrypted output will be written.

    Returns
    -------
    dict with keys:
        encrypted_filename  – basename of the written encrypted file
        key_b64             – URL-safe base64-encoded 32-byte AES key
        plaintext_sha256    – hex SHA-256 of original plaintext
        original_filename   – source filename
        file_size_bytes     – original file size in bytes
        encrypted_at        – ISO-8601 UTC timestamp

    Raises
    ------
    PathTraversalError      – filename contains path separators
    DemoFileNotFoundError   – filename not found in demo_dir
    FileSizeLimitError      – file exceeds size limit
    """
    _validate_basename(filename, "demo_filename")

    demo_dir = demo_dir.resolve()
    encrypted_dir = encrypted_dir.resolve()
    encrypted_dir.mkdir(parents=True, exist_ok=True)

    input_path = (demo_dir / filename).resolve()
    _assert_within(input_path, demo_dir, "demo file")

    if not input_path.is_file():
        raise DemoFileNotFoundError(
            f"Demo file '{filename}' not found in the demo directory."
        )

    file_size = input_path.stat().st_size
    if file_size > _DEMO_MAX_FILE_SIZE:
        raise FileSizeLimitError(
            f"Demo file '{filename}' is {file_size} bytes, "
            f"which exceeds the {_DEMO_MAX_FILE_SIZE // (1024 * 1024)} MB limit."
        )

    plaintext = input_path.read_bytes()
    key = demo_crypto.generate_key()
    blob = demo_crypto.encrypt(plaintext, key)
    key_b64 = base64.urlsafe_b64encode(key).decode()

    # Output filename: <uuid>_<original_basename>.csde
    unique_prefix = str(uuid4())[:8]
    encrypted_filename = f"{unique_prefix}_{filename}.csde"
    output_path = (encrypted_dir / encrypted_filename).resolve()
    _assert_within(output_path, encrypted_dir, "encrypted output")

    output_path.write_bytes(blob)

    plaintext_sha256 = demo_crypto.extract_plaintext_sha256_hex(blob)

    logger.info(
        "Demo file '%s' encrypted → '%s' (%d bytes plaintext).",
        filename,
        encrypted_filename,
        file_size,
    )

    return {
        "encrypted_filename": encrypted_filename,
        "key_b64": key_b64,
        "plaintext_sha256": plaintext_sha256,
        "original_filename": filename,
        "file_size_bytes": file_size,
        "encrypted_at": _utc_now_iso(),
    }


def _sanitize_filename(name: str) -> str:
    """Sanitize user-provided filename to prevent path traversal or unsafe characters."""
    base = Path(name).name.strip()
    if not base:
        base = "custom_file.bin"
    # Replace unsafe characters with underscore, keeping alphanumeric, period, dash, underscore
    sanitized = re.sub(r"[^\w\s\.-]", "_", base)
    sanitized = sanitized.lstrip(".")
    return sanitized or "custom_file.bin"


def encrypt_custom_file(
    file_bytes: bytes,
    original_filename: str,
    encrypted_dir: Path,
) -> dict:
    """
    Encrypt a custom benign file provided by the user with AES-256-GCM.

    The encrypted blob is written to *encrypted_dir* with a safe generated name.
    The key is returned in the result dict and is NOT stored server-side.
    """
    if len(file_bytes) > _DEMO_MAX_FILE_SIZE:
        raise FileSizeLimitError(
            f"Uploaded file is {len(file_bytes)} bytes, "
            f"which exceeds the {_DEMO_MAX_FILE_SIZE // (1024 * 1024)} MB limit."
        )

    safe_name = _sanitize_filename(original_filename)
    encrypted_dir = encrypted_dir.resolve()
    encrypted_dir.mkdir(parents=True, exist_ok=True)

    key = demo_crypto.generate_key()
    blob = demo_crypto.encrypt(file_bytes, key)
    key_b64 = base64.urlsafe_b64encode(key).decode()

    unique_prefix = str(uuid4())[:8]
    encrypted_filename = f"{unique_prefix}_{safe_name}.csde"
    output_path = (encrypted_dir / encrypted_filename).resolve()
    _assert_within(output_path, encrypted_dir, "encrypted output")

    output_path.write_bytes(blob)
    plaintext_sha256 = demo_crypto.extract_plaintext_sha256_hex(blob)

    logger.info(
        "Custom file '%s' encrypted → '%s' (%d bytes plaintext).",
        safe_name,
        encrypted_filename,
        len(file_bytes),
    )

    return {
        "encrypted_filename": encrypted_filename,
        "key_b64": key_b64,
        "plaintext_sha256": plaintext_sha256,
        "original_filename": safe_name,
        "file_size_bytes": len(file_bytes),
        "encrypted_at": _utc_now_iso(),
    }


def save_uploaded_encrypted_file(
    file_bytes: bytes,
    original_filename: str,
    encrypted_dir: Path,
) -> dict:
    """
    Save an uploaded pre-existing .csde file into encrypted_dir after verifying format.
    """
    if len(file_bytes) > _DEMO_MAX_FILE_SIZE:
        raise FileSizeLimitError(
            f"Uploaded encrypted file is {len(file_bytes)} bytes, "
            f"which exceeds the {_DEMO_MAX_FILE_SIZE // (1024 * 1024)} MB limit."
        )

    if len(file_bytes) < demo_crypto.MIN_BLOB_SIZE:
        raise InvalidFormatError(
            f"Uploaded file is too short ({len(file_bytes)} bytes). "
            f"Minimum valid CyberShield Demo Encrypted size is {demo_crypto.MIN_BLOB_SIZE} bytes."
        )

    magic = file_bytes[:4]
    if magic != demo_crypto.MAGIC:
        raise InvalidFormatError(
            f"Invalid magic bytes {magic!r}. "
            f"Expected {demo_crypto.MAGIC!r} (CyberShield Demo Encrypted file)."
        )

    version = file_bytes[4]
    if version != demo_crypto.CURRENT_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported format version {version}. "
            f"This engine supports version {demo_crypto.CURRENT_VERSION} only."
        )

    safe_name = _sanitize_filename(original_filename)
    if not safe_name.endswith(".csde"):
        safe_name = f"{safe_name}.csde"

    encrypted_dir = encrypted_dir.resolve()
    encrypted_dir.mkdir(parents=True, exist_ok=True)

    unique_prefix = str(uuid4())[:8]
    encrypted_filename = f"{unique_prefix}_{safe_name}"
    output_path = (encrypted_dir / encrypted_filename).resolve()
    _assert_within(output_path, encrypted_dir, "encrypted file upload")

    output_path.write_bytes(file_bytes)

    logger.info(
        "Uploaded encrypted file '%s' saved as '%s' (%d bytes).",
        safe_name,
        encrypted_filename,
        len(file_bytes),
    )

    return {
        "encrypted_filename": encrypted_filename,
        "original_filename": safe_name,
        "file_size_bytes": len(file_bytes),
    }


def get_encrypted_file_path(encrypted_filename: str, encrypted_dir: Path) -> Path:
    """Return verified path to an encrypted .csde file, ensuring containment."""
    _validate_basename(encrypted_filename, "encrypted_filename")
    encrypted_dir = encrypted_dir.resolve()
    path = (encrypted_dir / encrypted_filename).resolve()
    _assert_within(path, encrypted_dir, "encrypted file")
    if not path.is_file():
        raise EncryptedFileNotFoundError(f"Encrypted file '{encrypted_filename}' not found.")
    return path


def create_demo_decrypt_job(
    encrypted_dir: Path,
    encrypted_filename: str,
    key_b64: str,
    output_dir: Path,
    db: Optional[Session] = None,
    sample_id: Optional[str] = None,
) -> dict:
    """
    Create a demo decryption job, execute it synchronously, and return
    the completed job record.

    The job is stored in the database and in-memory cache so
    it persists across server restarts and can be retrieved via get_job().

    Duplicate protection: if a job for *encrypted_filename* is already
    RECOVERY_IN_PROGRESS, JobAlreadyRunningError is raised.
    """
    _validate_basename(encrypted_filename, "encrypted_filename")

    encrypted_dir = encrypted_dir.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    encrypted_path = (encrypted_dir / encrypted_filename).resolve()
    _assert_within(encrypted_path, encrypted_dir, "encrypted file")

    if not encrypted_path.is_file():
        raise EncryptedFileNotFoundError(
            f"Encrypted file '{encrypted_filename}' not found."
        )

    # Decode and validate key length before creating the job.
    try:
        key = base64.urlsafe_b64decode(key_b64 + "==")  # padding-tolerant
    except Exception as exc:
        raise InvalidKeyError(
            f"key_b64 is not valid URL-safe base64: {exc}"
        ) from exc

    if len(key) != demo_crypto.KEY_SIZE:
        raise InvalidKeyError(
            f"Decoded key must be {demo_crypto.KEY_SIZE} bytes; "
            f"got {len(key)} bytes."
        )

    job_id = str(uuid4())

    with _jobs_lock:
        # Duplicate-in-progress check.
        existing_id = _active_encrypted.get(encrypted_filename)
        if existing_id:
            existing = _jobs.get(existing_id, {})
            if existing.get("status") == RecoveryStatus.RECOVERY_IN_PROGRESS:
                raise JobAlreadyRunningError(
                    f"A decryption job ({existing_id}) for "
                    f"'{encrypted_filename}' is already in progress. "
                    f"Wait for it to complete."
                )

        job: dict = {
            "job_id": job_id,
            "sample_id": sample_id,
            "job_type": "DEMO",
            "status": RecoveryStatus.RECOVERY_IN_PROGRESS,
            "input_file": encrypted_filename,
            "output_path": None,
            "plaintext_sha256": None,
            "output_sha256": None,
            "verified": False,
            "error_message": None,
            "created_at": _utc_now_iso(),
            "completed_at": None,
        }
        _jobs[job_id] = job
        _active_encrypted[encrypted_filename] = job_id

    _persist_job(job, db=db)
    logger.info("Demo decrypt job %s started for '%s'.", job_id, encrypted_filename)

    # --- Execute decryption (synchronous) ---
    _run_demo_decrypt(job, encrypted_path, key, output_dir, db=db)

    return dict(job)


def get_job(job_id: str, db: Optional[Session] = None) -> dict | None:
    """
    Return a copy of the job record, or None if not found.
    Queries in-memory cache first, then falls back to SQLite database.
    """
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job:
            return dict(job)

    from app.database.database import SessionLocal
    from app.repositories.decryption_job_repository import DecryptionJobRepository

    try:
        if db is not None:
            db_job = DecryptionJobRepository.get_by_id(db, job_id)
        else:
            session = SessionLocal()
            try:
                db_job = DecryptionJobRepository.get_by_id(session, job_id)
            finally:
                session.close()

        if db_job:
            with _jobs_lock:
                _jobs[job_id] = db_job
            return dict(db_job)
    except Exception as exc:
        logger.error("Error retrieving decryption job %s from database: %s", job_id, exc)

    return None


def list_jobs(job_type: str | None = None, db: Optional[Session] = None) -> list[dict]:
    """
    Return all job records, optionally filtered by *job_type* ('DEMO'/'REAL').
    Queries SQLite database first to ensure historical persistence across restarts.
    """
    from app.database.database import SessionLocal
    from app.repositories.decryption_job_repository import DecryptionJobRepository

    try:
        if db is not None:
            db_jobs = DecryptionJobRepository.get_all(db, job_type=job_type)
        else:
            session = SessionLocal()
            try:
                db_jobs = DecryptionJobRepository.get_all(session, job_type=job_type)
            finally:
                session.close()

        if db_jobs:
            with _jobs_lock:
                for j in db_jobs:
                    if j["job_id"] not in _jobs:
                        _jobs[j["job_id"]] = j
            return [dict(j) for j in db_jobs]
    except Exception as exc:
        logger.error("Error listing decryption jobs from database: %s", exc)

    with _jobs_lock:
        jobs = list(_jobs.values())

    if job_type:
        jobs = [j for j in jobs if j.get("job_type") == job_type.upper()]

    return [dict(j) for j in jobs]


# ---------------------------------------------------------------------------
# Internal execution
# ---------------------------------------------------------------------------


def _run_demo_decrypt(
    job: dict,
    encrypted_path: Path,
    key: bytes,
    output_dir: Path,
    db: Optional[Session] = None,
) -> None:
    """
    Perform the actual decryption and verification; update *job* in place.

    This function NEVER raises — all exceptions are caught and recorded
    in the job record and database so the API can return a structured error response.
    """
    try:
        blob = encrypted_path.read_bytes()
        plaintext_sha256 = demo_crypto.extract_plaintext_sha256_hex(blob)

        with _jobs_lock:
            job["plaintext_sha256"] = plaintext_sha256

        # AES-GCM authenticated decryption.
        plaintext = demo_crypto.decrypt(blob, key)

        # Determine output filename from job_id to prevent collisions.
        original_name = _strip_csde_suffix(encrypted_path.name)
        clean_name = re.sub(r"^[0-9a-fA-F]{8}_", "", original_name)
        output_filename = f"recovered_{job['job_id'][:8]}_{clean_name}"
        output_path = (output_dir / output_filename).resolve()
        _assert_within(output_path, output_dir, "recovery output")

        # Prevent accidental overwrite (should not happen with UUID prefix).
        if output_path.exists():
            raise FileExistsError(
                f"Output path already exists: {output_path}. "
                "This is unexpected and may indicate a UUID collision."
            )

        output_path.write_bytes(plaintext)

        # --- Verification (read back from disk) ---
        output_sha256 = verification.compute_file_sha256(output_path)
        verified = verification.verify_demo_output(output_path, plaintext_sha256 or "")

        final_status = (
            RecoveryStatus.RECOVERY_SUCCEEDED
            if verified
            else RecoveryStatus.OUTPUT_VERIFICATION_FAILED
        )

        with _jobs_lock:
            job["status"] = final_status
            job["output_path"] = str(output_path)
            job["output_sha256"] = output_sha256
            job["verified"] = verified
            job["completed_at"] = _utc_now_iso()
            # Clear from active set regardless of outcome.
            _active_encrypted.pop(job["input_file"], None)

        _persist_job(job, db=db)
        logger.info(
            "Demo decrypt job %s → %s (verified=%s).",
            job["job_id"],
            final_status,
            verified,
        )

    except (
        TamperedCiphertextError,
        InvalidFormatError,
        InvalidKeyError,
        UnsupportedVersionError,
        IntegrityError,
        PathTraversalError,
        FileExistsError,
        OSError,
        Exception,
    ) as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        logger.error(
            "Demo decrypt job %s failed: %s",
            job["job_id"],
            error_msg,
        )
        with _jobs_lock:
            job["status"] = RecoveryStatus.RECOVERY_FAILED
            job["error_message"] = error_msg
            job["completed_at"] = _utc_now_iso()
            _active_encrypted.pop(job.get("input_file", ""), None)

        _persist_job(job, db=db)


# ---------------------------------------------------------------------------
# Path safety helpers
# ---------------------------------------------------------------------------


def _validate_basename(name: str, field: str) -> None:
    """Raise PathTraversalError if *name* contains path separators."""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise PathTraversalError(
            f"'{field}' must be a simple filename with no path separators "
            f"or leading dots. Got: {name!r}"
        )


def _assert_within(resolved_path: Path, base_dir: Path, label: str) -> None:
    """Raise PathTraversalError if *resolved_path* is outside *base_dir*."""
    try:
        resolved_path.relative_to(base_dir)
    except ValueError:
        raise PathTraversalError(
            f"Resolved {label} path '{resolved_path}' is outside "
            f"the approved directory '{base_dir}'. "
            "Operation aborted."
        )


def _strip_csde_suffix(filename: str) -> str:
    """Remove the .csde extension to reconstruct the original filename."""
    if filename.endswith(".csde"):
        return filename[:-5]
    return filename


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()
