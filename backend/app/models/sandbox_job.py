from typing import Any, Optional
from sqlalchemy import ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base


class SandboxJob(Base):
    """
    Database model representing an isolated container sandbox dynamic analysis job.
    Persists job lifecycle, security assertions, analysis results, and telemetry.
    """

    __tablename__ = "sandbox_jobs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    sample_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("samples.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        default="QUEUED",
    )

    created_at: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    completed_at: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    operations_run: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    process_tree: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
    )

    network_beacons: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
    )

    runtime_events: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
    )

    security_verifications: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    execution_summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    sample = relationship(
        "Sample",
        back_populates="sandbox_jobs",
    )
