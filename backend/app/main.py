from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.database import Base, engine

# Import models so SQLAlchemy registers them before create_all()
from app.models.sample import Sample
from app.models.analysis import Analysis

# Import API routers
from app.api.upload import router as upload_router
from app.api.sample import router as sample_router
from app.api.delete import router as delete_router


# ---------------------------------------------------------
# Create database tables
# ---------------------------------------------------------
Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------
# Create FastAPI application
# ---------------------------------------------------------
app = FastAPI(
    title="CyberShield - Ransomware Analysis API",
    description=(
        "Static malware and ransomware analysis API. "
        "The system analyzes uploaded files without executing them."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------
# CORS
# Allows the frontend to communicate with FastAPI.
# ---------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# Register API routers
#
# IMPORTANT:
# The routers already contain their own prefixes.
# Therefore we DO NOT add another "/api" prefix here.
# ---------------------------------------------------------
app.include_router(upload_router)
app.include_router(sample_router)
app.include_router(delete_router)


# ---------------------------------------------------------
# Root endpoint
# ---------------------------------------------------------
@app.get("/")
def root():
    return {
        "name": "CyberShield",
        "status": "running",
        "message": "CyberShield API is running successfully.",
    }


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "database": "connected",
    }