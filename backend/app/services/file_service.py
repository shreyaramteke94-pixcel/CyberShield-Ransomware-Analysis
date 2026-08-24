from pathlib import Path
from uuid import uuid4
import sys

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.repositories.sample_repository import SampleRepository
from app.services.analysis_services import AnalysisServices
from app.utils.hash import calculate_sha256


# ---------------------------------------------------------
# Connect ransomware_detection module
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RANSOMWARE_MODULE = PROJECT_ROOT / "ransomware_detection"

if str(RANSOMWARE_MODULE) not in sys.path:
    sys.path.insert(0, str(RANSOMWARE_MODULE))

from src.analyzer import Analyzer
from src.file_features import extract_features


class FileService:
    """
    Handles the complete CyberShield upload workflow.

    Upload
        ↓
    Save file
        ↓
    Save sample in database
        ↓
    Static analysis
        ↓
    Ransomware ML analysis
        ↓
    Return combined result
    """

    @staticmethod
    async def save_file(
        db: Session,
        file: UploadFile,
    ) -> dict:

        # -------------------------------------------------
        # Validate filename
        # -------------------------------------------------

        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is missing.",
            )

        original_filename = file.filename

        # -------------------------------------------------
        # Get extension
        # -------------------------------------------------

        extension = (
            Path(original_filename)
            .suffix
            .lower()
            .replace(".", "")
        )

        # -------------------------------------------------
        # Validate extension
        # -------------------------------------------------

        allowed_extensions = [
            ext.strip().lower()
            for ext in settings.ALLOWED_EXTENSIONS.split(",")
        ]

        if extension not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: .{extension}",
            )

        # -------------------------------------------------
        # Create upload directory
        # -------------------------------------------------

        upload_directory = Path(
            settings.UPLOAD_DIR
        )

        upload_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        # -------------------------------------------------
        # Generate sample ID
        # -------------------------------------------------

        sample_id = str(uuid4())

        # -------------------------------------------------
        # Generate stored filename
        # -------------------------------------------------

        stored_filename = (
            f"{sample_id}.{extension}"
        )

        file_path = (
            upload_directory
            / stored_filename
        )

        # -------------------------------------------------
        # Save uploaded file
        # -------------------------------------------------

        try:

            with file_path.open("wb") as buffer:

                while True:

                    chunk = await file.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    buffer.write(chunk)

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Failed to save uploaded file: {exc}"
                ),
            )

        # -------------------------------------------------
        # Calculate SHA-256
        # -------------------------------------------------

        try:

            sha256 = calculate_sha256(
                file_path
            )

        except Exception as exc:

            if file_path.exists():
                file_path.unlink()

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Failed to calculate file hash: {exc}"
                ),
            )

        # -------------------------------------------------
        # Get file size
        # -------------------------------------------------

        file_size = file_path.stat().st_size

        # -------------------------------------------------
        # Save sample metadata
        # -------------------------------------------------

        try:

            sample = SampleRepository.create(
                db=db,

                # IMPORTANT:
                # Your repository requires sample_id.
                sample_id=sample_id,

                original_filename=original_filename,

                stored_filename=stored_filename,

                file_extension=extension,

                file_size=file_size,

                sha256=sha256,
            )

        except Exception as exc:

            if file_path.exists():
                file_path.unlink()

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Failed to save sample metadata: {exc}"
                ),
            )

        # -------------------------------------------------
        # Existing static analysis
        # -------------------------------------------------

        try:

            analysis = AnalysisServices.analyze(
                db=db,
                sample_id=sample.id,
                file_path=file_path,
            )

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Static analysis failed: {exc}"
                ),
            )

        # -------------------------------------------------
        # Ransomware detection module
        # -------------------------------------------------

        try:

            file_data = file_path.read_bytes()

            ransomware_features = extract_features(
                original_filename,
                file_data,
            )

            ransomware_analyzer = Analyzer()

            ransomware_result = (
                ransomware_analyzer.analyze(
                    ransomware_features
                )
            )

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    "Ransomware detection failed: "
                    f"{exc}"
                ),
            )

        # -------------------------------------------------
        # Combined response
        # -------------------------------------------------

        return {
            "sample_id": sample.id,

            "status": sample.status,

            "filename": original_filename,

            "stored_filename": stored_filename,

            "file_size": file_size,

            "sha256": sha256,

            # Existing CyberShield analysis
            "analysis": analysis,

            # ML + ransomware risk analysis
            "ransomware_detection": ransomware_result,
        }