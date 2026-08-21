from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.repositories.sample_repository import SampleRepository
from app.repositories.analysis_repository import AnalysisRepository


class DeleteService:

    @staticmethod
    def delete_sample(
        db: Session,
        sample_id: str,
    ):

        sample = SampleRepository.get_by_id(
            db,
            sample_id,
        )

        if sample is None:
            raise HTTPException(
                status_code=404,
                detail="Sample not found."
            )

        analysis = AnalysisRepository.get_by_sample_id(
            db,
            sample_id,
        )

        if analysis:
            AnalysisRepository.delete(
                db,
                analysis,
            )

        file_path = (
            Path(settings.UPLOAD_DIR)
            / sample.stored_filename
        )

        if file_path.exists():
            file_path.unlink()

        SampleRepository.delete(
            db,
            sample,
        )

        return {
            "message": "Sample deleted successfully."
        }