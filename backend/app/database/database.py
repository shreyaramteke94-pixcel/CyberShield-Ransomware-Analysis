from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

# SQLite database file.
#
# Because Uvicorn is started from the backend directory:
#
#     cd backend
#     python -m uvicorn app.main:app --reload
#
# this creates:
#
#     backend/cybershield.db
#
DATABASE_URL = "sqlite:///./cybershield.db"


# ============================================================
# DATABASE ENGINE
# ============================================================

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    }
)


# ============================================================
# DATABASE SESSION
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# ============================================================
# BASE MODEL
# ============================================================

Base = declarative_base()


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def get_db():
    """
    Creates a database session for a FastAPI request.

    The session is automatically closed after the request
    finishes.
    """

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()