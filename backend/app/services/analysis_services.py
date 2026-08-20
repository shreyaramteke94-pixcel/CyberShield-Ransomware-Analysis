from pathlib import Path
from datetime import datetime, timezone
import mimetypes
import math

from sqlalchemy.orm import Session

from app.repositories.analysis_repository import AnalysisRepository
from app.utils.hash import calculate_sha256
from app.utils.pe_parser import PEParser


class AnalysisServices:
    """
    Performs safe static analysis on an uploaded file.

    This service does not execute the sample.
    """

    @staticmethod
    def calculate_entropy(file_path: Path) -> float:
        """
        Calculate Shannon entropy for the complete file.
        """

        data = file_path.read_bytes()

        if not data:
            return 0.0

        frequency = [0] * 256

        for byte in data:
            frequency[byte] += 1

        length = len(data)

        entropy = 0.0

        for count in frequency:
            if count:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    @staticmethod
    def analyze(
        db: Session,
        sample_id: str,
        file_path: Path,
    ) -> dict:
        """
        Perform basic static analysis and save
        the results to the database.
        """

        # --------------------------------
        # Check file exists
        # --------------------------------

        if not file_path.exists():
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        # --------------------------------
        # Basic file information
        # --------------------------------

        stat = file_path.stat()

        extension = (
            file_path.suffix
            .lower()
            .lstrip(".")
        )

        mime_type, _ = mimetypes.guess_type(
            file_path.name
        )

        # --------------------------------
        # SHA-256
        # --------------------------------

        sha256 = calculate_sha256(file_path)

        # --------------------------------
        # Entropy
        # --------------------------------

        entropy = AnalysisServices.calculate_entropy(
            file_path
        )

        # --------------------------------
        # PE analysis
        # --------------------------------

        pe_analysis = None

        if extension in ["exe", "dll", "sys", "scr"]:
            pe_analysis = PEParser.parse(file_path)

        # --------------------------------
        # Save analysis to database
        # --------------------------------

        final_mime_type = (
            mime_type
            or "application/octet-stream"
        )

        existing = AnalysisRepository.get_by_sample_id(
            db=db,
            sample_id=sample_id,
        )

        if existing:
            AnalysisRepository.update(
                db=db,
                analysis=existing,
                mime_type=final_mime_type,
                entropy=entropy,
                pe_analysis=pe_analysis,
            )

        else:
            AnalysisRepository.create(
                db=db,
                sample_id=sample_id,
                mime_type=final_mime_type,
                entropy=entropy,
                pe_analysis=pe_analysis,
            )

        # --------------------------------
        # Return analysis result
        # --------------------------------

        return {
            "filename": file_path.name,
            "extension": extension,
            "mime_type": final_mime_type,
            "file_size": stat.st_size,
            "sha256": sha256,
            "entropy": entropy,
            "created_at": datetime.fromtimestamp(
                stat.st_ctime,
                tz=timezone.utc,
            ).isoformat(),
            "modified_at": datetime.fromtimestamp(
                stat.st_mtime,
                tz=timezone.utc,
            ).isoformat(),
            "pe_analysis": pe_analysis,
        }