from pathlib import Path
from uuid import uuid4
import shutil
import sys

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.repositories.sample_repository import SampleRepository
from app.services.analysis_services import AnalysisServices
from app.utils.hash import calculate_sha256


# ============================================================
# RANSOMWARE DETECTION MODULE
# ============================================================

# Project root:
# CyberShield-Ransomware-Analysis/
#
# This file:
# backend/app/services/file_service.py
#
# Therefore parents[3] points to the project root.

RANSOMWARE_MODULE = (
    Path(__file__).resolve().parents[3]
    / "ransomware_detection"
)

if str(RANSOMWARE_MODULE) not in sys.path:
    sys.path.insert(0, str(RANSOMWARE_MODULE))


from src.analyzer import Analyzer
from src.file_features import extract_features


class FileService:
    """
    Handles the complete file upload and analysis workflow.

    Workflow:
        Upload file
            ↓
        Save file
            ↓
        Calculate SHA-256
            ↓
        Save sample metadata
            ↓
        Existing static analysis
            ↓
        Ransomware detection
            ↓
        Return combined result
    """

    # Load the ransomware analyzer once.
    ransomware_analyzer = Analyzer()

    @staticmethod
    def save_file(
        db: Session,
        file: UploadFile,
    ):
        # ====================================================
        # 1. Validate filename
        # ====================================================

        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="Filename is missing.",
            )

        # ====================================================
        # 2. Validate extension
        # ====================================================

        extension = (
            Path(file.filename)
            .suffix
            .lower()
            .replace(".", "")
        )

        allowed_extensions = [
            ext.strip().lower()
            for ext in settings.ALLOWED_EXTENSIONS.split(",")
        ]

        if extension not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: .{extension}",
            )

        # ====================================================
        # 3. Create upload directory
        # ====================================================

        upload_dir = Path(settings.UPLOAD_DIR)

        upload_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ====================================================
        # 4. Generate unique filename
        # ====================================================

        file_id = str(uuid4())

        stored_filename = (
            f"{file_id}.{extension}"
        )

        destination = (
            upload_dir / stored_filename
        )

        # ====================================================
        # 5. Save uploaded file
        # ====================================================

        try:
            with destination.open("wb") as buffer:
                shutil.copyfileobj(
                    file.file,
                    buffer,
                )

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Failed to save uploaded file: {exc}"
                ),
            )

        # ====================================================
        # 6. Calculate SHA-256
        # ====================================================

        sha256 = calculate_sha256(
            destination
        )

        # ====================================================
        # 7. Get file size
        # ====================================================

        file_size = destination.stat().st_size

        # ====================================================
        # 8. Save sample metadata
        # ====================================================

        try:
            sample = SampleRepository.create(
                db=db,
                original_filename=file.filename,
                stored_filename=stored_filename,
                file_extension=extension,
                file_size=file_size,
                sha256=sha256,
            )

        except Exception as exc:

            # Remove physical file if
            # database operation fails.

            if destination.exists():
                destination.unlink()

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Failed to save sample metadata: {exc}"
                ),
            )

        # ====================================================
        # 9. Existing static analysis
        # ====================================================

        try:

            analysis = AnalysisServices.analyze(
                db=db,
                sample_id=sample.id,
                file_path=destination,
            )

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    f"File analysis failed: {exc}"
                ),
            )

        # ====================================================
        # 10. Ransomware Detection
        # ====================================================

        try:

            # Read the saved file safely as bytes.
            #
            # The ransomware module performs static
            # analysis. It does NOT execute the file.

            file_data = destination.read_bytes()

            # Extract features required by Analyzer:
            #
            # - file_size
            # - entropy
            # - suspicious_extension
            # - yara_match_count
            # - threat_intelligence_score
            # - sha256
            # - extension

            ransomware_features = extract_features(
                file.filename,
                file_data,
            )

            # Run ML prediction + risk engine.

            ransomware_result = (
                FileService.ransomware_analyzer.analyze(
                    ransomware_features
                )
            )

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Ransomware analysis failed: {exc}"
                ),
            )

        # ====================================================
        # 11. Return combined response
        # ====================================================

        return {
            "sample_id": sample.id,

            "status": sample.status,

            # Existing FastAPI static analysis
            "analysis": analysis,

            # Ransomware detection module
            "ransomware_detection": {
                "ml_prediction": (
                    ransomware_result.get(
                        "ml_prediction"
                    )
                ),

                "ml_probability": (
                    ransomware_result.get(
                        "ml_probability"
                    )
                ),

                "risk_score": (
                    ransomware_result.get(
                        "risk_score"
                    )
                ),

                "risk_level": (
                    ransomware_result.get(
                        "risk_level"
                    )
                ),

                "reasons": (
                    ransomware_result.get(
                        "reasons",
                        []
                    )
                ),
            },
        }