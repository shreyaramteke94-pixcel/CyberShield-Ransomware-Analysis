from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database.database import Base, engine
from app.api.upload import router as upload_router
from app.api.sample import router as sample_router
from app.api.delete import router as delete_router

# Import models so SQLAlchemy can discover them
from app.models.sample import Sample
from app.models.analysis import Analysis

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise Ransomware Analysis Platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Root"])
async def root():
    return JSONResponse(
        content={
            "application": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "running",
        }
    )


@app.get("/health", tags=["Health"])
async def health():
    return JSONResponse(
        content={
            "status": "healthy",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
        }
    )


app.include_router(upload_router)
app.include_router(sample_router)
app.include_router(delete_router)