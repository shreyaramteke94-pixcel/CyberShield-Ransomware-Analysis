from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


class Sample(Base):
    """
    Database model representing an uploaded sample.
    """

    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4())
    )

    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    stored_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True
    )

    file_extension: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="uploaded"
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )