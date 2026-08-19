from pathlib import Path
from uuid import uuid4
import shutil

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.repositories.sample_repository import SampleRepository
from app.services.analysis_services import AnalysisServices


class FileService:
    """
    Handles the complete upload workflow.
    """

    @staticmethod
    def save_file(
        db: Session,
        file: UploadFile,
    ):

        # ----------------------------
        # Validate filename
        # ----------------------------
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is missing."
            )

        # ----------------------------
        # Validate extension
        # ----------------------------
        extension = (
            Path(file.filename)
            .suffix
            .lower()
            .replace(".", "")
        )

        allowed_extensions = [
            ext.strip().lower()
            for ext in settings.ALLOWED_EXTENSIONS.split(",")
        ]

        if extension not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: .{extension}"
            )

        # ----------------------------
        # Create upload directory
        # ----------------------------
        upload_dir = Path(settings.UPLOAD_DIR)

        upload_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------
        # Generate unique filename
        # ----------------------------
        file_id = str(uuid4())

        stored_filename = f"{file_id}.{extension}"

        destination = upload_dir / stored_filename

        # ----------------------------
        # Save file
        # ----------------------------
        with destination.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # ----------------------------
        # Analyze the uploaded file
        # ----------------------------
        analysis = AnalysisServices.analyze(destination)

        # ----------------------------
        # Save metadata to database
        # ----------------------------
        sample = SampleRepository.create(
            db=db,
            original_filename=file.filename,
            stored_filename=stored_filename,
            file_extension=extension,
            file_size=analysis["file_size"],
            sha256=analysis["sha256"],
        )

        # ----------------------------
        # Return response
        # ----------------------------
        return {
            "sample_id": sample.id,
            "status": sample.status,
            "analysis": analysis,
        }