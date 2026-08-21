from sqlalchemy.orm import Session

from app.models.sample import Sample


class SampleRepository:
    """
    Handles all database operations related to uploaded samples.
    """
    @staticmethod
    def create(
        db: Session,
        original_filename: str,
        stored_filename: str,
        file_extension: str,
        file_size: int,
        sha256: str,
    ) -> Sample:

        sample = Sample(
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
    ):

        return (
            db.query(Sample)
            .filter(Sample.id == sample_id)
            .first()
        )

    @staticmethod
    def get_all(
        db: Session,
    ):

        return (
            db.query(Sample)
            .order_by(Sample.uploaded_at.desc())
            .all()
        )

    @staticmethod
    def update_status(
        db: Session,
        sample: Sample,
        status: str,
    ):

        sample.status = status

        db.commit()
        db.refresh(sample)

        return sample

    @staticmethod
    def delete(
        db: Session,
        sample: Sample,
    ):

        db.delete(sample)
        db.commit()