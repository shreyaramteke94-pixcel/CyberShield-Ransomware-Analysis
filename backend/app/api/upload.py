from fastapi import APIRouter, File, UploadFile

from app.services.file_service import FileService

router = APIRouter(
    prefix="/api/v1/upload",
    tags=["Upload"]
)


@router.post("/")
async def upload_file(
    file: UploadFile = File(...)
):
    """
    Upload a ransomware sample.
    """

    return FileService.save_file(file)