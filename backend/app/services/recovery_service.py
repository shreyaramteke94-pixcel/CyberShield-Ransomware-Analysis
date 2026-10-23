from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.repositories.sample_repository import SampleRepository


class RecoveryService:
    """Validate a sample before attempting supported recovery."""

    @staticmethod
    def check_recovery(
        db: Session,
        sample_id: str,
    ) -> dict:
        sample = SampleRepository.get_by_id(
            db=db,
            sample_id=sample_id,
        )

        if sample is None:
            raise HTTPException(
                status_code=404,
                detail="Sample not found.",
            )

        upload_dir = Path(settings.UPLOAD_DIR).resolve()
        file_path = (upload_dir / sample.stored_filename).resolve()

        # Ensure the resolved path stays inside the upload directory.
        if file_path.parent != upload_dir:
            raise HTTPException(
                status_code=400,
                detail="Invalid stored file path.",
            )

        if not file_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="Stored sample file not found.",
            )

        return {
            "sample_id": sample.id,
            "filename": sample.original_filename,
            "recovery_status": "DECRYPTOR_UNAVAILABLE",
            "recovered": False,
            "message": (
                "The sample exists, but no compatible verified "
                "decryptor is configured. The original file was "
                "not modified."
            ),
        }