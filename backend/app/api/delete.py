from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.delete_service import DeleteService

router = APIRouter(
    prefix="/api/v1",
    tags=["Delete"],
)


@router.delete("/samples/{sample_id}")
def delete_sample(
    sample_id: str,
    db: Session = Depends(get_db),
):
    return DeleteService.delete_sample(
        db,
        sample_id,
    )