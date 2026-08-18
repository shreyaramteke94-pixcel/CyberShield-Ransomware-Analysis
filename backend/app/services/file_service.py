from pathlib import Path
from uuid import uuid4
import shutil

from fastapi import UploadFile, HTTPException

from app.config import settings


class FileService:
    """
    Handles all file upload operations.
    """

    @staticmethod
    def save_file(file: UploadFile) -> dict:

        # Validate filename
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is missing."
            )

        # Extract extension
        extension = Path(file.filename).suffix.lower().replace(".", "")

        # Validate extension
        allowed_extensions = [
            ext.strip().lower()
            for ext in settings.ALLOWED_EXTENSIONS.split(",")
        ]

        if extension not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: .{extension}"
            )

        # Create upload directory
        upload_dir = Path(settings.UPLOAD_DIR)
        upload_dir.mkdir(parents=True, exist_ok=True)

        # Generate unique filename
        file_id = str(uuid4())
        stored_filename = f"{file_id}.{extension}"

        destination = upload_dir / stored_filename

        # Save file
        with destination.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = destination.stat().st_size

        return {
            "file_id": file_id,
            "original_filename": file.filename,
            "stored_filename": stored_filename,
            "extension": extension,
            "size": file_size,
            "status": "uploaded"
        }