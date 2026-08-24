
from sqlalchemy.orm import Session

from app.models.sample import Sample


class SampleRepository:
    """
    Handles database operations related to uploaded samples.
    """

    @staticmethod
    def create(
        db: Session,
        sample_id: str,
        original_filename: str,
        stored_filename: str,
        file_extension: str,
        file_size: int,
        sha256: str | None = None,
    ) -> Sample:
        sample = Sample(
            id=sample_id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_extension=file_extension,
            file_size=file_size,
            sha256=sha256,
            status="uploaded",
        )

        db.add(sample)
        db.commit()
        db.refresh(sample)

        return sample

    @staticmethod
    def get_by_id(
        db: Session,
        sample_id: str,
    ) -> Sample | None:
        return (
            db.query(Sample)
            .filter(Sample.id == sample_id)
            .first()
        )

    @staticmethod
    def get_all(
        db: Session,
    ) -> list[Sample]:
        return (
            db.query(Sample)
            .order_by(Sample.uploaded_at.desc())
            .all()
        )

    @staticmethod
    def delete(
        db: Session,
        sample: Sample,
    ) -> None:
        db.delete(sample)
        db.commit()

