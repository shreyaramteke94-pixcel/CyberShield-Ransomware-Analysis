import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.models.sandbox_job import SandboxJob
from app.sandbox.schemas import SandboxJobResponse, SandboxStatus

logger = logging.getLogger(__name__)


class SandboxJobRepository:
    """
    Handles database operations and persistence for sandbox dynamic analysis jobs.
    """

    @staticmethod
    def to_schema(model: SandboxJob) -> SandboxJobResponse:
        """Convert a SandboxJob SQLAlchemy model instance to a SandboxJobResponse schema."""
        status_val = model.status
        try:
            status_enum = SandboxStatus(status_val)
        except ValueError:
            status_enum = SandboxStatus.FAILED

        return SandboxJobResponse(
            job_id=model.id,
            sample_id=model.sample_id or "",
            filename=model.filename,
            status=status_enum,
            created_at=model.created_at,
            completed_at=model.completed_at,
            operations_run=model.operations_run or [],
            error_message=model.error_message,
            process_tree=model.process_tree or [],
            network_beacons=model.network_beacons or [],
            runtime_events=model.runtime_events or [],
            security_verifications=model.security_verifications or {},
            execution_summary=model.execution_summary or "",
        )

    @staticmethod
    def create_or_update(db: Session, job: SandboxJobResponse) -> SandboxJob:
        """Insert or update a SandboxJob record in the database."""
        status_str = job.status.value if isinstance(job.status, SandboxStatus) else str(job.status)
        record = db.query(SandboxJob).filter(SandboxJob.id == job.job_id).first()
        if not record:
            record = SandboxJob(
                id=job.job_id,
                sample_id=job.sample_id if job.sample_id else None,
                filename=job.filename,
                status=status_str,
                created_at=job.created_at,
                completed_at=job.completed_at,
                operations_run=job.operations_run,
                error_message=job.error_message,
                process_tree=job.process_tree,
                network_beacons=job.network_beacons,
                runtime_events=job.runtime_events,
                security_verifications=job.security_verifications,
                execution_summary=job.execution_summary,
            )
            db.add(record)
        else:
            record.status = status_str
            record.completed_at = job.completed_at
            record.operations_run = job.operations_run
            record.error_message = job.error_message
            record.process_tree = job.process_tree
            record.network_beacons = job.network_beacons
            record.runtime_events = job.runtime_events
            record.security_verifications = job.security_verifications
            record.execution_summary = job.execution_summary

        try:
            db.commit()
            db.refresh(record)
        except Exception as exc:
            db.rollback()
            logger.error("Failed to commit sandbox job %s to database: %s", job.job_id, exc)
            raise

        return record

    @staticmethod
    def get_by_id(db: Session, job_id: str) -> Optional[SandboxJobResponse]:
        """Retrieve a sandbox job by UUID from the database."""
        record = db.query(SandboxJob).filter(SandboxJob.id == job_id).first()
        return SandboxJobRepository.to_schema(record) if record else None

    @staticmethod
    def get_all(db: Session) -> list[SandboxJobResponse]:
        """List all sandbox jobs ordered newest first."""
        records = db.query(SandboxJob).order_by(SandboxJob.created_at.desc()).all()
        return [SandboxJobRepository.to_schema(r) for r in records]

    @staticmethod
    def get_by_sample_id(db: Session, sample_id: str) -> list[SandboxJobResponse]:
        """List all sandbox jobs for a specific sample ID."""
        records = (
            db.query(SandboxJob)
            .filter(SandboxJob.sample_id == sample_id)
            .order_by(SandboxJob.created_at.desc())
            .all()
        )
        return [SandboxJobRepository.to_schema(r) for r in records]
