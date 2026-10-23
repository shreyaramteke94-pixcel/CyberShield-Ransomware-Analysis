
from pathlib import Path
from uuid import uuid4
import sys

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.repositories.sample_repository import SampleRepository
from app.services.analysis_services import AnalysisServices
from app.utils.hash import calculate_sha256


# Connect the ransomware detection module.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RANSOMWARE_MODULE = PROJECT_ROOT / "ransomware_detection"

if str(RANSOMWARE_MODULE) not in sys.path:
    sys.path.insert(0, str(RANSOMWARE_MODULE))

from src.analyzer import Analyzer
from src.file_features import extract_features


class FileService:
    """Handle file uploads, static analysis, and ML detection."""

    @staticmethod
    def _determine_overall_verdict(
        analysis: dict,
        ransomware_result: dict,
    ) -> str:
        """Combine static and ML indicators into a cautious verdict."""

        static_score = int(analysis.get("risk_score", 0) or 0)
        static_severity = str(
            analysis.get("severity", "LOW")
        ).upper()

        yara_matches = analysis.get("yara_matches") or []

        ml_risk_level = str(
            ransomware_result.get("risk_level", "LOW")
        ).upper()

        # High-risk static findings take priority over the ML result.
        if (
            static_severity in {"HIGH", "CRITICAL"}
            or static_score >= 50
        ):
            return "HIGH_RISK"

        # A benign ML prediction does not override static indicators.
        if (
            yara_matches
            or static_severity == "MEDIUM"
            or static_score >= 20
            or ml_risk_level in {"MEDIUM", "HIGH"}
        ):
            return "SUSPICIOUS"

        return "LOW_RISK"

    @staticmethod
    async def save_file(
        db: Session,
        file: UploadFile,
    ) -> dict:
        # Validate filename presence.
        if not file.filename or not file.filename.strip():
            raise HTTPException(
                status_code=400,
                detail="Filename is missing or empty.",
            )

        raw_filename = file.filename

        # Reject URL-encoded bypasses, path traversal, path separators, null bytes, control characters.
        import urllib.parse
        decoded_filename = urllib.parse.unquote(raw_filename)

        if (
            "\x00" in raw_filename
            or "\x00" in decoded_filename
            or "%00" in raw_filename.lower()
            or any(ord(c) < 32 for c in raw_filename)
            or any(ord(c) < 32 for c in decoded_filename)
        ):
            raise HTTPException(
                status_code=400,
                detail="Filename contains invalid control characters or null bytes.",
            )

        if (
            "/" in raw_filename
            or "\\" in raw_filename
            or "/" in decoded_filename
            or "\\" in decoded_filename
        ):
            raise HTTPException(
                status_code=400,
                detail="Filename contains invalid path separators.",
            )

        if ".." in raw_filename or ".." in decoded_filename:
            raise HTTPException(
                status_code=400,
                detail="Path traversal sequences are not permitted in filenames.",
            )

        original_filename = Path(raw_filename).name
        if not original_filename or original_filename.startswith("."):
            raise HTTPException(
                status_code=400,
                detail="Invalid filename format.",
            )

        # Validate extension.
        extension = (
            Path(original_filename)
            .suffix
            .lower()
            .replace(".", "")
        )

        if not extension:
            raise HTTPException(
                status_code=400,
                detail="File extension is missing.",
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

        # Create upload directory and verify containment.
        upload_directory = Path(settings.UPLOAD_DIR).resolve()
        upload_directory.mkdir(parents=True, exist_ok=True)

        sample_id = str(uuid4())
        stored_filename = f"{sample_id}.{extension}"
        file_path = (upload_directory / stored_filename).resolve()

        if file_path.parent != upload_directory:
            raise HTTPException(
                status_code=400,
                detail="Invalid upload storage destination.",
            )

        # Stream upload with strict chunk-by-chunk size limit enforcement.
        max_size = settings.MAX_FILE_SIZE
        total_bytes = 0

        try:
            with file_path.open("wb") as buffer:
                while True:
                    chunk = await file.read(64 * 1024)
                    if not chunk:
                        break

                    # Enforce limit before writing chunk to disk
                    if total_bytes + len(chunk) > max_size:
                        buffer.close()
                        if file_path.exists():
                            file_path.unlink()
                        raise HTTPException(
                            status_code=413,
                            detail=f"File exceeds maximum allowed size of {max_size} bytes.",
                        )

                    buffer.write(chunk)
                    total_bytes += len(chunk)

        except HTTPException:
            if file_path.exists():
                file_path.unlink()
            raise
        except Exception as exc:
            if file_path.exists():
                file_path.unlink()
            raise HTTPException(
                status_code=500,
                detail="Failed to save uploaded file.",
            ) from exc

        # Check for empty file.
        if total_bytes == 0:
            if file_path.exists():
                file_path.unlink()
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty.",
            )

        # Calculate SHA-256.
        try:
            sha256 = calculate_sha256(file_path)
        except Exception as exc:
            if file_path.exists():
                file_path.unlink()
            raise HTTPException(
                status_code=500,
                detail="Failed to calculate file hash.",
            ) from exc

        file_size = total_bytes

        # Save sample metadata.
        sample = None
        try:
            sample = SampleRepository.create(
                db=db,
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
                detail="Failed to save sample metadata.",
            ) from exc

        # Run static analysis.
        try:
            analysis = AnalysisServices.analyze(
                db=db,
                sample_id=sample.id,
                file_path=file_path,
                original_filename=original_filename,
            )
        except Exception as exc:
            if file_path.exists():
                file_path.unlink()
            if sample:
                try:
                    SampleRepository.delete(db=db, sample=sample)
                except Exception:
                    pass
            raise HTTPException(
                status_code=500,
                detail="Static analysis failed.",
            ) from exc

        # Run ML analysis using the static YARA results.
        try:
            file_data = file_path.read_bytes()
            yara_matches = analysis.get("yara_matches", [])

            ransomware_features = extract_features(
                filename=original_filename,
                data=file_data,
                yara_match_count=len(yara_matches),
            )

            ransomware_analyzer = Analyzer()
            ransomware_result = ransomware_analyzer.analyze(
                ransomware_features
            )
        except Exception as exc:
            if file_path.exists():
                file_path.unlink()
            if sample:
                try:
                    SampleRepository.delete(db=db, sample=sample)
                except Exception:
                    pass
            raise HTTPException(
                status_code=500,
                detail="Ransomware detection failed.",
            ) from exc

        # Combine indicators without overwriting either risk score.
        overall_verdict = FileService._determine_overall_verdict(
            analysis=analysis,
            ransomware_result=ransomware_result,
        )

        # Return combined results.
        return {
            "sample_id": sample.id,
            "status": sample.status,
            "filename": original_filename,
            "stored_filename": stored_filename,
            "file_size": file_size,
            "sha256": sha256,
            "overall_verdict": overall_verdict,
            "analysis": analysis,
            "ransomware_detection": ransomware_result,
        }
