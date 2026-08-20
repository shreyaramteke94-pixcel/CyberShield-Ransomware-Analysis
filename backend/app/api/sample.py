from fastapi import APIRouter, Depends
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
    return SampleRepository.get_all(db)


@router.get("/{sample_id}")
def get_sample(
    sample_id: str,
    db: Session = Depends(get_db),
):
    sample = SampleRepository.get_by_id(
        db,
        sample_id,
    )

    if sample is None:
        return {
            "message": "Sample not found"
        }

    return sample