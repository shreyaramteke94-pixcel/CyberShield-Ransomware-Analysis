
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.repositories.sample_repository import SampleRepository


router = APIRouter(
    prefix="/api/v1/samples",
    tags=["Samples"],
)


@router.get("/")
def get_samples(
    db: Session = Depends(get_db),
):
    """
    Return all uploaded samples.
    """

    return SampleRepository.get_all(db=db)


@router.get("/{sample_id}")
def get_sample(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """
    Return a single uploaded sample by ID.
    """

    sample = SampleRepository.get_by_id(
        db=db,
        sample_id=sample_id,
    )

    if sample is None:
        raise HTTPException(
            status_code=404,
            detail="Sample not found.",
        )

    return sample


@router.delete("/{sample_id}")
def delete_sample(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """
    Delete a sample from the database.
    """

    sample = SampleRepository.get_by_id(
        db=db,
        sample_id=sample_id,
    )

    if sample is None:
        raise HTTPException(
            status_code=404,
            detail="Sample not found.",
        )

    SampleRepository.delete(
        db=db,
        sample=sample,
    )

    return {
        "message": "Sample deleted successfully.",
        "sample_id": sample_id,
    }

