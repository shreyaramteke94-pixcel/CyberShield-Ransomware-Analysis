from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base


class Analysis(Base):
    """
    Database model representing the analysis results
    of an uploaded sample.
    """

    __tablename__ = "analysis"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    sample_id: Mapped[str] = mapped_column(
        ForeignKey("samples.id"),
        unique=True,
        nullable=False,
    )

    mime_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    entropy: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    pe_analysis: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    yara_matches: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    suspicious_strings: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="LOW",
    )

    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    sample = relationship(
        "Sample",
        back_populates="analysis",
    )