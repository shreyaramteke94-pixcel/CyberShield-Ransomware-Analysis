from typing import Optional
from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base


class DecryptionJob(Base):
    """
    Database model representing a decryption/recovery job.
    Persists job state, verification results, input and output file metadata.

    CRITICAL SECURITY POLICY:
    Encryption keys, plaintext secrets, and sensitive recovered contents
    are NEVER stored in this model or database table.
    """

    __tablename__ = "decryption_jobs"

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

    job_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="DEMO",
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        default="READY_FOR_RECOVERY",
    )

    input_file: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    output_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    plaintext_sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    output_sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    completed_at: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    sample = relationship(
        "Sample",
        back_populates="decryption_jobs",
    )
