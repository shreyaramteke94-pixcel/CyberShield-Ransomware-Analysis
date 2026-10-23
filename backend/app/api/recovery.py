from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.recovery_service import RecoveryService


router = APIRouter(
    prefix="/api/v1/recovery",
    tags=["Recovery"],
)


@router.post("/{sample_id}/check")
def check_recovery(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """Check whether a stored sample is ready for supported recovery."""

    return RecoveryService.check_recovery(
        db=db,
        sample_id=sample_id,
    )