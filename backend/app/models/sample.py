
from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base


class Sample(Base):
    """
    Database model representing an uploaded file.
    """

    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    stored_filename: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )

    file_extension: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="uploaded",
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    analysis = relationship(
        "Analysis",
        back_populates="sample",
        uselist=False,
        cascade="all, delete-orphan",
    )

