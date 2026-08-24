from fastapi import APIRouter
from fastapi import Depends
from fastapi import File
from fastapi import UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.sample import Sample


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    tags=["Samples"]
)


# ============================================================
# UPLOAD SAMPLE
# ============================================================

@router.post("/upload")
async def upload_sample(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Receives a file from the React frontend and stores
    its metadata in the SQLite database.
    """

    # --------------------------------------------------------
    # Read uploaded file
    # --------------------------------------------------------

    contents = await file.read()

    file_size = len(contents)

    # --------------------------------------------------------
    # Create database record
    # --------------------------------------------------------

    sample = Sample(
        filename=file.filename or "unknown",
        file_size=file_size,
        file_type=file.content_type or "unknown",
        status="uploaded"
    )

    # --------------------------------------------------------
    # Save record
    # --------------------------------------------------------

    db.add(sample)

    db.commit()

    db.refresh(sample)

    # --------------------------------------------------------
    # Return result to React
    # --------------------------------------------------------

    return {
        "success": True,
        "message": "Sample uploaded successfully",

        "sample": {
            "id": sample.id,
            "filename": sample.filename,
            "file_size": sample.file_size,
            "file_type": sample.file_type,
            "status": sample.status,
            "created_at": sample.created_at
        }
    }


# ============================================================
# GET ALL SAMPLES
# ============================================================

@router.get("/samples")
def get_samples(
    db: Session = Depends(get_db)
):
    """
    Returns all samples stored in the database.
    """

    samples = (
        db.query(Sample)
        .order_by(Sample.created_at.desc())
        .all()
    )

    return {
        "success": True,
        "count": len(samples),
        "samples": [
            {
                "id": sample.id,
                "filename": sample.filename,
                "file_size": sample.file_size,
                "file_type": sample.file_type,
                "md5": sample.md5,
                "sha256": sample.sha256,
                "verdict": sample.verdict,
                "family": sample.family,
                "confidence": sample.confidence,
                "status": sample.status,
                "created_at": sample.created_at
            }
            for sample in samples
        ]
    }


# ============================================================
# GET ONE SAMPLE
# ============================================================

@router.get("/samples/{sample_id}")
def get_sample(
    sample_id: int,
    db: Session = Depends(get_db)
):
    """
    Returns one sample by database ID.
    """

    sample = (
        db.query(Sample)
        .filter(Sample.id == sample_id)
        .first()
    )

    if sample is None:
        return {
            "success": False,
            "message": "Sample not found"
        }

    return {
        "success": True,
        "sample": {
            "id": sample.id,
            "filename": sample.filename,
            "file_size": sample.file_size,
            "file_type": sample.file_type,
            "md5": sample.md5,
            "sha256": sample.sha256,
            "verdict": sample.verdict,
            "family": sample.family,
            "confidence": sample.confidence,
            "status": sample.status,
            "created_at": sample.created_at
        }
    }