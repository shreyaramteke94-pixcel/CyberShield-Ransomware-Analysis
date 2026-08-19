from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.config import settings
from app.api.upload import router as upload_router

from app.database.database import Base, engine

# Import models so SQLAlchemy can discover them
from app.models.sample import Sample

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise Ransomware Analysis Platform",
    docs_url="/docs",
    redoc_url="/redoc",
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