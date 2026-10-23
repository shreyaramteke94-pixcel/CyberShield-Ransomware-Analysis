"""
FastAPI router for the CyberShield Decryption & Recovery Engine.

Prefix: /api/v1/decryption

Endpoints
---------
GET  /api/v1/decryption/demo/files                       – List available demo plaintext files
POST /api/v1/decryption/demo/encrypt                     – Encrypt a demo file (returns key once)
POST /api/v1/decryption/demo/jobs                        – Start a demo decryption job
GET  /api/v1/decryption/demo/jobs                        – List all demo jobs (no key material)
GET  /api/v1/decryption/demo/jobs/{job_id}               – Get job status and verification result
GET  /api/v1/decryption/demo/jobs/{job_id}/download      – Download the recovered plaintext file
GET  /api/v1/decryption/registry                         – List all registered decryptor adapters
POST /api/v1/decryption/{sample_id}/eligibility          – Check real-recovery eligibility

Key-safety rules enforced here
-------------------------------
- The demo key (key_b64) appears ONLY in the DemoEncryptResponse.
- It is NOT stored server-side and NOT returned in any job status response.
- Job history never contains key material.
- Server filesystem paths are redacted from responses (only basenames exposed).
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import get_db
from app.decryption import orchestrator, registry, compatibility
from app.decryption.exceptions import (
    DemoFileNotFoundError,
    EncryptedFileNotFoundError,
    FileSizeLimitError,
    InvalidFormatError,
    InvalidKeyError,
    JobAlreadyRunningError,
    PathTraversalError,
    UnsupportedVersionError,
)
from app.decryption.schemas import (
    DecryptorInfo,
    DemoDecryptRequest,
    DemoDecryptResponse,
    DemoEncryptRequest,
    DemoEncryptResponse,
    DemoFileInfo,
    DemoFilesResponse,
    EligibilityResponse,
    JobStatusResponse,
    RegistryResponse,
    UploadEncryptedResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/decryption", tags=["Decryption Engine"])

# ---------------------------------------------------------------------------
# Resolved directory paths
# ---------------------------------------------------------------------------

def _demo_dir() -> Path:
    """Absolute path to the demo plaintext files directory."""
    # __file__ = backend/app/api/decrypt.py
    # parents[2] = backend/
    return (Path(__file__).resolve().parents[2] / "demo_files").resolve()


def _encrypted_dir() -> Path:
    return (_demo_dir() / "encrypted").resolve()


def _output_dir() -> Path:
    return Path(settings.RECOVERY_OUTPUT_DIR).resolve()


# ---------------------------------------------------------------------------
# Demo file listing
# ---------------------------------------------------------------------------


@router.get(
    "/demo/files",
    response_model=DemoFilesResponse,
    summary="List available demo plaintext files",
)
def list_demo_files():
    """
    Return metadata for all plaintext demo files available for the
    controlled decryption demonstration.
    """
    files_meta = orchestrator.list_demo_input_files(_demo_dir())
    return DemoFilesResponse(
        files=[
            DemoFileInfo(
                filename=f["filename"],
                size_bytes=f["size_bytes"],
                description=f["description"],
            )
            for f in files_meta
        ]
    )


# ---------------------------------------------------------------------------
# Demo encryption
# ---------------------------------------------------------------------------


@router.post(
    "/demo/encrypt",
    response_model=DemoEncryptResponse,
    summary="Encrypt a demo file for controlled demonstration",
    status_code=status.HTTP_201_CREATED,
)
def encrypt_demo_file(req: DemoEncryptRequest):
    """
    Encrypt a demo plaintext file with a freshly generated AES-256-GCM key.

    **The key is returned ONCE in this response and is NOT stored server-side.**
    Save the key immediately if you intend to demonstrate decryption.

    This endpoint only operates on files from the server-side demo directory.
    It does not accept file uploads and does not touch analysed ransomware samples.
    """
    try:
        result = orchestrator.encrypt_demo_file(
            demo_dir=_demo_dir(),
            filename=req.demo_filename,
            encrypted_dir=_encrypted_dir(),
        )
    except PathTraversalError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except DemoFileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except FileSizeLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        )
    except Exception as exc:
        logger.error("Unexpected error during demo encryption: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Demo encryption failed due to an internal error.",
        )

    from datetime import datetime, timezone
    return DemoEncryptResponse(
        encrypted_filename=result["encrypted_filename"],
        key_b64=result["key_b64"],
        plaintext_sha256=result["plaintext_sha256"],
        original_filename=result["original_filename"],
        file_size_bytes=result["file_size_bytes"],
        encrypted_at=result["encrypted_at"],
    )


# ---------------------------------------------------------------------------
# Custom file encryption (user uploads their own file)
# ---------------------------------------------------------------------------


_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


@router.post(
    "/custom/encrypt",
    response_model=DemoEncryptResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Encrypt a user-uploaded file with AES-256-GCM (demo)",
)
async def encrypt_custom_file(file: UploadFile = File(...)):
    """
    Accept any benign file upload, encrypt it with a freshly generated
    AES-256-GCM key, and return the key ONCE.

    **The key is NOT stored server-side.** Save it immediately.
    This endpoint never executes uploaded files.
    """
    filename = file.filename or "custom_file.bin"
    file_bytes = await file.read()
    if len(file_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
        )
    if len(file_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded file is empty.",
        )
    try:
        result = orchestrator.encrypt_custom_file(
            file_bytes=file_bytes,
            original_filename=filename,
            encrypted_dir=_encrypted_dir(),
        )
    except PathTraversalError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except FileSizeLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        )
    except Exception as exc:
        logger.error("Unexpected error during custom file encryption: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Custom file encryption failed due to an internal error.",
        )

    return DemoEncryptResponse(
        encrypted_filename=result["encrypted_filename"],
        key_b64=result["key_b64"],
        plaintext_sha256=result["plaintext_sha256"],
        original_filename=result["original_filename"],
        file_size_bytes=result["file_size_bytes"],
        encrypted_at=result["encrypted_at"],
    )


@router.post(
    "/custom/upload-encrypted",
    response_model=UploadEncryptedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a pre-existing .csde encrypted file",
)
async def upload_encrypted_file(file: UploadFile = File(...)):
    """
    Accept a pre-existing CyberShield Demo Encrypted (.csde) file,
    validate its magic bytes and version, and save it to the encrypted
    directory so it can be decrypted via the normal jobs endpoint.

    Only valid .csde files are accepted. The file is never executed.
    """
    filename = file.filename or "uploaded.csde"
    if not filename.lower().endswith(".csde"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only .csde files are accepted by this endpoint.",
        )
    file_bytes = await file.read()
    if len(file_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
        )
    try:
        result = orchestrator.save_uploaded_encrypted_file(
            file_bytes=file_bytes,
            original_filename=filename,
            encrypted_dir=_encrypted_dir(),
        )
    except (InvalidFormatError, UnsupportedVersionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except FileSizeLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        )
    except PathTraversalError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Unexpected error saving encrypted upload: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded encrypted file.",
        )

    return UploadEncryptedResponse(
        encrypted_filename=result["encrypted_filename"],
        original_filename=result["original_filename"],
        file_size_bytes=result["file_size_bytes"],
    )


@router.get(
    "/custom/encrypted/{filename}/download",
    summary="Download a custom .csde encrypted file",
    response_class=FileResponse,
)
def download_custom_encrypted_file(filename: str):
    """
    Download an encrypted .csde file stored in the encrypted directory
    (i.e. one produced by /custom/encrypt or saved by /custom/upload-encrypted).

    Path-traversal is blocked: *filename* must be a simple basename.
    """
    # Reject path separators or leading dots.
    if not filename or "/" in filename or "\\" in filename or filename.startswith("."):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="'filename' must be a simple basename with no path separators.",
        )
    if not filename.lower().endswith(".csde"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .csde files can be downloaded from this endpoint.",
        )

    encrypted_dir = _encrypted_dir()
    file_path = (encrypted_dir / filename).resolve()

    try:
        file_path.relative_to(encrypted_dir)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Resolved path is outside the encrypted files directory.",
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Encrypted file '{filename}' not found.",
        )

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Demo decryption jobs
# ---------------------------------------------------------------------------


@router.post(
    "/demo/jobs",
    response_model=JobStatusResponse,
    summary="Start a demo decryption job",
    status_code=status.HTTP_201_CREATED,
)
def start_demo_decrypt_job(
    req: DemoDecryptRequest,
    db: Session = Depends(get_db),
):
    """
    Submit an encrypted demo file and its key for authenticated decryption.

    - Uses real AES-256-GCM decryption (not simulated).
    - Returns RECOVERY_SUCCEEDED only after the output integrity check passes.
    - Returns RECOVERY_FAILED or OUTPUT_VERIFICATION_FAILED on any error.

    The key is consumed for decryption and is not stored in the job record.
    """
    try:
        job = orchestrator.create_demo_decrypt_job(
            encrypted_dir=_encrypted_dir(),
            encrypted_filename=req.encrypted_filename,
            key_b64=req.key_b64,
            output_dir=_output_dir(),
            db=db,
            sample_id=req.sample_id,
        )
    except PathTraversalError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except InvalidKeyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except EncryptedFileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except JobAlreadyRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except Exception as exc:
        logger.error("Unexpected error starting demo job: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start demo decryption job.",
        )

    return _job_to_response(job)


@router.get(
    "/demo/jobs",
    response_model=list[JobStatusResponse],
    summary="List all demo decryption jobs",
)
def list_demo_jobs(
    db: Session = Depends(get_db),
):
    """
    Return all demo decryption jobs from database/store.
    Job records never contain key material.
    Server filesystem paths are replaced with basenames.
    """
    jobs = orchestrator.list_jobs(job_type="DEMO", db=db)
    return [_job_to_response(j) for j in jobs]


@router.get(
    "/demo/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Get demo job status and verification result",
)
def get_demo_job(
    job_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve the status and integrity verification result for a demo job.
    Returns 404 if the job_id is not found.
    """
    job = orchestrator.get_job(job_id, db=db)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Demo job '{job_id}' not found.",
        )
    return _job_to_response(job)


@router.get(
    "/demo/jobs/{job_id}/download",
    summary="Download the recovered plaintext file for a completed demo job",
    response_class=FileResponse,
)
def download_demo_job_output(
    job_id: str,
    db: Session = Depends(get_db),
):
    """
    Stream the recovered plaintext file for a demo decryption job.

    Requirements:
    - Job must exist (404 otherwise).
    - Job status must be RECOVERY_SUCCEEDED and verified=True (400 otherwise).
    - Resolved output path must be within RECOVERY_OUTPUT_DIR (400 on traversal).
    - File must exist on disk (500 if unexpectedly missing).

    Server filesystem paths are never exposed in the response body.
    The Content-Disposition header carries only the recovered file basename.
    """
    job = orchestrator.get_job(job_id, db=db)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Demo job '{job_id}' not found.",
        )

    if job.get("status") != "RECOVERY_SUCCEEDED" or not job.get("verified"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Job '{job_id}' cannot be downloaded: status is "
                f"'{job.get('status')}', verified={job.get('verified')}. "
                "Only RECOVERY_SUCCEEDED jobs with verified=True can be downloaded."
            ),
        )

    # The orchestrator stores the full server path in output_path.
    raw_output_path = job.get("output_path")
    if not raw_output_path:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Job completed but output_path is missing. Cannot serve file.",
        )

    output_path = Path(raw_output_path).resolve()
    approved_dir = _output_dir()

    # Path-traversal guard: resolved path must be inside RECOVERY_OUTPUT_DIR.
    try:
        output_path.relative_to(approved_dir)
    except ValueError:
        logger.error(
            "Download blocked: job %s output_path %s is outside approved dir %s.",
            job_id, output_path, approved_dir,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Output path is outside the approved recovery directory.",
        )

    if not output_path.is_file():
        logger.error(
            "Download requested for job %s but file not found: %s", job_id, output_path
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recovered file is no longer present on disk.",
        )

    return FileResponse(
        path=str(output_path),
        filename=output_path.name,
        media_type="application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Decryptor registry
# ---------------------------------------------------------------------------


@router.get(
    "/registry",
    response_model=RegistryResponse,
    summary="List registered decryptor adapters and their status",
)
def list_decryptors():
    """
    Return all registered decryptor adapters with their capabilities,
    availability status, prerequisites, and limitations.

    Availability reflects the current server environment. No adapter claims
    AVAILABLE status unless all prerequisites are actually satisfied.
    """
    adapters = registry.list_adapters()
    available = registry.available_count()
    return RegistryResponse(
        adapters=[
            DecryptorInfo(
                adapter_id=a.adapter_id,
                display_name=a.display_name,
                source=a.source,
                supported_families=a.supported_families,
                supported_variants=a.supported_variants,
                status=a.status,
                prerequisites=a.prerequisites,
                limitations=a.limitations,
                can_run_automatically=a.can_run_automatically,
                requires_explicit_approval=a.requires_explicit_approval,
            )
            for a in adapters
        ],
        total=len(adapters),
        available_count=available,
    )


# ---------------------------------------------------------------------------
# Real-sample eligibility check
# ---------------------------------------------------------------------------


@router.post(
    "/{sample_id}/eligibility",
    response_model=EligibilityResponse,
    summary="Check real ransomware recovery eligibility for a sample",
)
def check_eligibility(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """
    Evaluate whether a supported recovery method exists for an analysed sample.

    This endpoint reads the sample's existing analysis from the database and
    consults the decryptor registry. It never starts decryption.

    Returns an honest status explaining whether recovery is possible,
    why it may not be, and what would be needed to proceed.
    """
    import re
    if not sample_id or not re.match(r"^[a-zA-Z0-9_\-]{1,64}$", sample_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sample ID format.",
        )

    from app.repositories.sample_repository import SampleRepository
    from app.repositories.analysis_repository import AnalysisRepository

    sample = SampleRepository.get_by_id(db=db, sample_id=sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample '{sample_id}' not found.",
        )

    analysis = AnalysisRepository.get_by_sample_id(db=db, sample_id=sample_id)
    analysis_dict = None
    identification_dict = None

    if analysis:
        analysis_dict = {
            "yara_matches": getattr(analysis, "yara_matches", None),
            "suspicious_strings": getattr(analysis, "suspicious_strings", None),
            "risk_score": getattr(analysis, "risk_score", 0),
            "severity": getattr(analysis, "severity", "LOW"),
            "extension": sample.file_extension,
        }
        identification_dict = {
            "ransomware_family": getattr(analysis, "ransomware_family", None),
            "cipher_algorithm": getattr(analysis, "cipher_algorithm", None),
            "confidence": getattr(analysis, "confidence", None),
            "identification_status": getattr(analysis, "identification_status", ""),
        }

    result = compatibility.check_eligibility(
        sample_id=sample_id,
        filename=sample.original_filename,
        identification_result=identification_dict,
        analysis_result=analysis_dict,
    )

    return EligibilityResponse(**result)


# ---------------------------------------------------------------------------
# Internal helper — sanitise job dict for API response
# ---------------------------------------------------------------------------


def _job_to_response(job: dict) -> JobStatusResponse:
    """
    Convert an orchestrator job dict to a JobStatusResponse.

    - output_path is reduced to just the basename (no server filesystem paths).
    - Key material is never present in job dicts, but explicitly excluded here
      as a defence-in-depth measure.
    """
    output_path = job.get("output_path")
    output_basename = Path(output_path).name if output_path else None

    return JobStatusResponse(
        job_id=job["job_id"],
        job_type=job["job_type"],
        status=job["status"],
        input_file=job.get("input_file"),
        output_path=output_basename,   # basename only, not full server path
        plaintext_sha256=job.get("plaintext_sha256"),
        output_sha256=job.get("output_sha256"),
        verified=job.get("verified", False),
        error_message=job.get("error_message"),
        created_at=job["created_at"],
        completed_at=job.get("completed_at"),
    )
