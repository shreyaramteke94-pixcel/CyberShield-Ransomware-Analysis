from datetime import datetime

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import Integer
from sqlalchemy import String

from app.database import Base


class Sample(Base):
    """
    Database model representing an uploaded malware sample.
    """

    __tablename__ = "samples"

    # --------------------------------------------------------
    # Primary key
    # --------------------------------------------------------

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    # --------------------------------------------------------
    # File information
    # --------------------------------------------------------

    filename = Column(
        String,
        nullable=False
    )

    file_size = Column(
        Integer,
        nullable=True
    )

    file_type = Column(
        String,
        nullable=True
    )

    # --------------------------------------------------------
    # Cryptographic hashes
    # --------------------------------------------------------

    md5 = Column(
        String,
        nullable=True,
        index=True
    )

    sha256 = Column(
        String,
        nullable=True,
        index=True
    )

    # --------------------------------------------------------
    # Analysis information
    # --------------------------------------------------------

    verdict = Column(
        String,
        nullable=True
    )

    family = Column(
        String,
        nullable=True
    )

    confidence = Column(
        Float,
        nullable=True
    )

    # --------------------------------------------------------
    # Processing status
    # --------------------------------------------------------

    status = Column(
        String,
        nullable=False,
        default="uploaded"
    )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )