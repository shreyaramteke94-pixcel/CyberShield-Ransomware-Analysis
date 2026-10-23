import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.models.decryption_job import DecryptionJob

logger = logging.getLogger(__name__)


class DecryptionJobRepository:
    """
    Handles database operations and persistence for decryption/recovery jobs.
    Key material is NEVER stored.
    """

    @staticmethod
    def to_dict(model: DecryptionJob) -> dict:
        """Convert a DecryptionJob model instance to a dictionary representation."""
        return {
            "job_id": model.id,
            "sample_id": model.sample_id,
            "job_type": model.job_type,
            "status": model.status,
            "input_file": model.input_file,
            "output_path": model.output_path,
            "plaintext_sha256": model.plaintext_sha256,
            "output_sha256": model.output_sha256,
            "verified": bool(model.verified),
            "error_message": model.error_message,
            "created_at": model.created_at,
            "completed_at": model.completed_at,
        }

    @staticmethod
    def create_or_update(db: Session, job: dict) -> DecryptionJob:
        """Insert or update a DecryptionJob record in the database."""
        job_id = job["job_id"]
        record = db.query(DecryptionJob).filter(DecryptionJob.id == job_id).first()
        if not record:
            record = DecryptionJob(
                id=job_id,
                sample_id=job.get("sample_id"),
                job_type=job.get("job_type", "DEMO"),
                status=job.get("status", "READY_FOR_RECOVERY"),
                input_file=job.get("input_file"),
                output_path=job.get("output_path"),
                plaintext_sha256=job.get("plaintext_sha256"),
                output_sha256=job.get("output_sha256"),
                verified=bool(job.get("verified", False)),
                error_message=job.get("error_message"),
                created_at=job.get("created_at"),
                completed_at=job.get("completed_at"),
            )
            db.add(record)
        else:
            record.status = job.get("status", record.status)
            record.output_path = job.get("output_path", record.output_path)
            record.plaintext_sha256 = job.get("plaintext_sha256", record.plaintext_sha256)
            record.output_sha256 = job.get("output_sha256", record.output_sha256)
            record.verified = bool(job.get("verified", record.verified))
            record.error_message = job.get("error_message", record.error_message)
            record.completed_at = job.get("completed_at", record.completed_at)

        try:
            db.commit()
            db.refresh(record)
        except Exception as exc:
            db.rollback()
            logger.error("Failed to commit decryption job %s to database: %s", job_id, exc)
            raise

        return record

    @staticmethod
    def get_by_id(db: Session, job_id: str) -> Optional[dict]:
        """Retrieve a decryption job by UUID from the database."""
        record = db.query(DecryptionJob).filter(DecryptionJob.id == job_id).first()
        return DecryptionJobRepository.to_dict(record) if record else None

    @staticmethod
    def get_all(db: Session, job_type: Optional[str] = None) -> list[dict]:
        """List all decryption jobs, optionally filtered by job_type."""
        query = db.query(DecryptionJob)
        if job_type:
            query = query.filter(DecryptionJob.job_type == job_type.upper())
        records = query.order_by(DecryptionJob.created_at.desc()).all()
        return [DecryptionJobRepository.to_dict(r) for r in records]
