"""
FastAPI router for Sample Management and Forensic Reporting.

Prefix: /api/v1/samples

Endpoints
---------
GET /api/v1/samples/              - List all uploaded samples
GET /api/v1/samples/{sample_id}   - Retrieve metadata for a specific sample
GET /api/v1/samples/{sample_id}/report - Retrieve or download standardized forensic report

Security rules:
- Sample IDs are validated against strict alphanumeric/UUID format (no traversal).
- Storage directory containment is asserted before any file access.
- No internal host paths or database secrets are leaked in responses.
- Honest authorization note: Multi-user tenant isolation is not implemented
  in the database layer; the list endpoint returns all repository samples.
"""

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import get_db
from app.repositories.sample_repository import SampleRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.decryption import compatibility

router = APIRouter(
    prefix="/api/v1/samples",
    tags=["Samples"],
)

# Strict sample ID format: UUID or safe alphanumeric string
SAMPLE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _validate_sample_id(sample_id: str) -> str:
    """Validate sample_id format and reject traversal attempts."""
    if not sample_id or not SAMPLE_ID_REGEX.match(sample_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sample ID format.",
        )
    return sample_id


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
    "/",
    summary="List uploaded samples",
)
def list_samples(
    db: Session = Depends(get_db),
):
    """
    List all uploaded samples in the repository.

    **Authorization note**: Per-user tenant isolation is not yet implemented
    in the database schema; all samples stored in the repository are returned.
    """
    samples = SampleRepository.get_all(db)
    sample_list = []
    for s in samples:
        sample_list.append(
            {
                "id": s.id,
                "original_filename": s.original_filename,
                "file_extension": s.file_extension,
                "file_size": s.file_size,
                "sha256": s.sha256,
                "status": s.status,
                "uploaded_at": s.uploaded_at.isoformat() if s.uploaded_at else None,
            }
        )

    return {
        "samples": sample_list,
        "total": len(sample_list),
        "auth_model_note": (
            "Multi-user database isolation is not enabled; "
            "listing includes all samples in the shared repository."
        ),
    }


@router.get(
    "/{sample_id}",
    summary="Get sample details",
)
def get_sample(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve metadata for a specific sample."""
    valid_id = _validate_sample_id(sample_id)
    sample = SampleRepository.get_by_id(db=db, sample_id=valid_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found.",
        )

    return {
        "id": sample.id,
        "original_filename": sample.original_filename,
        "file_extension": sample.file_extension,
        "file_size": sample.file_size,
        "sha256": sample.sha256,
        "status": sample.status,
        "uploaded_at": sample.uploaded_at.isoformat() if sample.uploaded_at else None,
    }


@router.get(
    "/{sample_id}/report",
    summary="Generate standardized forensic analysis report",
)
def get_sample_report(
    sample_id: str,
    download: bool = Query(
        default=False,
        description="Set to true to download the report as a JSON file attachment",
    ),
    db: Session = Depends(get_db),
):
    """
    Generate and return a standardized forensic analysis report for an analyzed sample.

    Includes sample metadata, Shannon entropy, static indicators, YARA matches,
    suspicious strings, risk score, and real-recovery eligibility status.
    """
    valid_id = _validate_sample_id(sample_id)
    sample = SampleRepository.get_by_id(db=db, sample_id=valid_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found.",
        )

    # Enforce path containment
    _verify_storage_containment(sample.stored_filename)

    analysis = AnalysisRepository.get_by_sample_id(db=db, sample_id=valid_id)
    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis results not found for this sample.",
        )

    # Compute recovery eligibility via compatibility checker
    analysis_dict = {
        "yara_matches": analysis.yara_matches or [],
        "suspicious_strings": analysis.suspicious_strings or [],
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "extension": sample.file_extension,
    }

    # Extract ransomware identification if present
    pe_info = analysis.pe_analysis or {}
    entropy_val = analysis.entropy

    eligibility = compatibility.check_eligibility(
        sample_id=sample.id,
        filename=sample.original_filename,
        identification_result={
            "ransomware_family": "Unknown",
            "cipher_algorithm": None,
            "confidence": None,
            "identification_status": "ANALYZED",
        },
        analysis_result=analysis_dict,
    )

    report_data = {
        "report_id": f"CSR-{sample.id}",
        "platform": "CyberShield Ransomware Analysis & Decryption Platform",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": "TLP:AMBER",
        "sample": {
            "id": sample.id,
            "original_filename": sample.original_filename,
            "file_size_bytes": sample.file_size,
            "file_extension": sample.file_extension,
            "sha256": sample.sha256,
            "uploaded_at": sample.uploaded_at.isoformat() if sample.uploaded_at else None,
            "status": sample.status,
        },
        "static_analysis": {
            "mime_type": analysis.mime_type,
            "entropy": entropy_val,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "yara_matches": analysis.yara_matches or [],
            "suspicious_strings": analysis.suspicious_strings or [],
            "pe_summary": {
                "machine": pe_info.get("machine"),
                "number_of_sections": pe_info.get("number_of_sections"),
                "entry_point": pe_info.get("entry_point"),
            } if pe_info else None,
            "analyzed_at": analysis.analyzed_at.isoformat() if analysis.analyzed_at else None,
        },
        "recovery_assessment": {
            "recovery_status": eligibility.get("recovery_status"),
            "compatible_adapters": eligibility.get("compatible_adapters", []),
            "limitations": eligibility.get("limitations", []),
            "explanation": eligibility.get("explanation"),
        },
        "remediation_guidance": [
            "Quarantine and preserve original host disk images before remediation.",
            "Verify backup integrity from offline / air-gapped storage.",
            "Inspect flagged suspicious strings and YARA indicators in enterprise EDR.",
            "Do not execute unknown binaries or third-party decryptors without verified provenance.",
        ],
    }

    if download:
        import json
        content = json.dumps(report_data, indent=2)
        safe_filename = f"CyberShield_Report_{sample.id[:8]}.json"
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_filename}"',
            },
        )

    return report_data
