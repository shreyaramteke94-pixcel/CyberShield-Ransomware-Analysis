from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.file_service import FileService


router = APIRouter(
    prefix="/api/v1/upload",
    tags=["Upload"],
)


@router.post("/")
async def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Upload a file and perform the complete
    CyberShield ransomware analysis.
    """

    return await FileService.save_file(
        db=db,
        file=file,
    )