"""
FastAPI Router for Sandbox Dynamic Analysis.

Prefix: /api/v1/sandbox

Endpoints:
- GET  /api/v1/sandbox/status          - Diagnostic status of Docker & container environment
- POST /api/v1/sandbox/jobs            - Submit a sample for isolated container dynamic analysis
- GET  /api/v1/sandbox/jobs/{job_id}   - Retrieve state and telemetry for a specific job
- GET  /api/v1/sandbox/jobs            - List all recorded sandbox jobs

Security policies:
- Strict sample ID format validation.
- Mandatory opt-in: confirm_dynamic_execution must be explicitly True.
- Host path containment verification before sample reference.
- Truthful reporting: UNAVAILABLE when container runtime is missing.
- Prohibition against fallback host execution.
"""

from pathlib import Path
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import get_db
from app.repositories.sample_repository import SampleRepository
from app.sandbox.detector import get_sandbox_status
from app.sandbox.manager import sandbox_manager
from app.sandbox.schemas import (
    SandboxDetectorResponse,
    SandboxJobRequest,
    SandboxJobResponse,
)

router = APIRouter(
    prefix="/api/v1/sandbox",
    tags=["Sandbox Dynamic Analysis"],
)

SAMPLE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
JOB_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _validate_id(identifier: str, field_name: str) -> str:
    """Validate identifier against alphanumeric/UUID pattern."""
    if not identifier or not SAMPLE_ID_REGEX.match(identifier):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name} format.",
        )
    return identifier


def _verify_storage_containment(stored_filename: str) -> Path:
    """Ensure stored sample path resolves strictly within the upload directory."""
    upload_dir = Path(settings.UPLOAD_DIR).resolve()
    target_path = (upload_dir / stored_filename).resolve()

    try:
        target_path.relative_to(upload_dir)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access to file path outside upload repository is forbidden.",
        )
    return target_path


@router.get(
    "/status",
    response_model=SandboxDetectorResponse,
    summary="Get sandbox environment readiness and diagnostic status",
)
def get_status() -> SandboxDetectorResponse:
    """
    Check whether Docker CLI, Docker daemon, and vetted sandbox image are available.

    Returns UNAVAILABLE with detailed remediation prerequisites if Docker is missing.
    """
    return get_sandbox_status()


@router.post(
    "/jobs",
    response_model=SandboxJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit sample to dynamic container sandbox analysis",
)
def submit_sandbox_job(
    request: SandboxJobRequest,
    db: Session = Depends(get_db),
) -> SandboxJobResponse:
    """
    Submit a statically-analyzed sample for dynamic execution in an isolated container.

    Requires explicit opt-in confirmation (`confirm_dynamic_execution: true`).
    If the Docker container runtime is not available on the host, creates an UNAVAILABLE
    job record with full diagnostics. Host execution is strictly prevented.
    """
    sample_id = _validate_id(request.sample_id, "sample_id")

    if not request.confirm_dynamic_execution:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit confirmation (confirm_dynamic_execution=true) is required for dynamic execution.",
        )

    sample = SampleRepository.get_by_id(db=db, sample_id=sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample '{sample_id}' not found in repository.",
        )

    target_path = _verify_storage_containment(sample.stored_filename)

    timeout = request.timeout_seconds if request.timeout_seconds is not None else 60

    job = sandbox_manager.create_job(
        sample_id=sample.id,
        filename=sample.original_filename,
        sample_path=target_path,
        confirm_dynamic_execution=request.confirm_dynamic_execution,
        timeout_seconds=timeout,
        db=db,
    )
    return job


@router.get(
    "/jobs/{job_id}",
    response_model=SandboxJobResponse,
    summary="Get sandbox job status and telemetry",
)
def get_sandbox_job(
    job_id: str,
    db: Session = Depends(get_db),
) -> SandboxJobResponse:
    """
    Retrieve execution state, telemetry, and diagnostics for a specific sandbox job.
    """
    valid_job_id = _validate_id(job_id, "job_id")
    job = sandbox_manager.get_job(valid_job_id, db=db)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sandbox job '{valid_job_id}' not found.",
        )
    return job


@router.get(
    "/jobs",
    response_model=list[SandboxJobResponse],
    summary="List all sandbox execution jobs",
)
def list_sandbox_jobs(
    db: Session = Depends(get_db),
) -> list[SandboxJobResponse]:
    """
    List all dynamic analysis jobs submitted during this application session.
    """
    return sandbox_manager.list_jobs(db=db)
