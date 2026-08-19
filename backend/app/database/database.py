from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy models.
    """
    pass


engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def get_db():
    """
    FastAPI dependency that provides a database session.
    """
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()