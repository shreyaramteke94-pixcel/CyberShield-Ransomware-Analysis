
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.repositories.sample_repository import SampleRepository
from app.repositories.analysis_repository import AnalysisRepository


router = APIRouter(
    prefix="/api/v1/analysis",
    tags=["Analysis"],
)


@router.get("/{sample_id}")
def get_analysis(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """Return saved static analysis results for a sample."""

    sample = SampleRepository.get_by_id(
        db=db,
        sample_id=sample_id,
    )

    if sample is None:
        raise HTTPException(
            status_code=404,
            detail="Sample not found.",
        )

    analysis = AnalysisRepository.get_by_sample_id(
        db=db,
        sample_id=sample_id,
    )

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No saved analysis results found for this sample.",
        )

    return {
        "sample_id": sample.id,
        "filename": sample.original_filename,
        "sha256": sample.sha256,
        "analysis": {
            "mime_type": analysis.mime_type,
            "entropy": analysis.entropy,
            "pe_analysis": analysis.pe_analysis,
            "yara_matches": analysis.yara_matches or [],
            "suspicious_strings": analysis.suspicious_strings or [],
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "analyzed_at": analysis.analyzed_at,
        },
    }
