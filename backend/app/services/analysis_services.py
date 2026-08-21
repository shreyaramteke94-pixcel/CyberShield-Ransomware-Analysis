from pathlib import Path
from datetime import datetime, timezone
import mimetypes
import math

from sqlalchemy.orm import Session

from app.repositories.analysis_repository import AnalysisRepository

from app.utils.hash import calculate_sha256
from app.utils.pe_parser import PEParser
from app.utils.yara_scanner import YaraScanner
from app.utils.string_extractor import StringExtractor


class AnalysisServices:
    """
    Performs safe static analysis on uploaded files.
    """

    @staticmethod
    def calculate_entropy(file_path: Path) -> float:

        data = file_path.read_bytes()

        if not data:
            return 0.0

        frequency = [0] * 256

        for byte in data:
            frequency[byte] += 1

        entropy = 0.0
        length = len(data)

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

        if not file_path.exists():
            raise FileNotFoundError(
                f"{file_path} does not exist."
            )

        stat = file_path.stat()

        extension = file_path.suffix.lower().replace(".", "")

        mime_type, _ = mimetypes.guess_type(
            file_path.name
        )

        mime_type = (
            mime_type
            or "application/octet-stream"
        )

        sha256 = calculate_sha256(file_path)

        entropy = AnalysisServices.calculate_entropy(
            file_path
        )

        pe_analysis = None

        if extension in [
            "exe",
            "dll",
            "sys",
            "scr",
        ]:
            pe_analysis = PEParser.parse(file_path)

        # -------------------------
        # YARA Scan
        # -------------------------

        yara_matches = YaraScanner.scan(
            file_path
        )

        # -------------------------
        # String Extraction
        # -------------------------

        all_strings = StringExtractor.extract(
            file_path
        )

        suspicious_strings = (
            StringExtractor.suspicious_strings(
                all_strings
            )
        )

        existing = (
            AnalysisRepository.get_by_sample_id(
                db=db,
                sample_id=sample_id,
            )
        )

        if existing:

            AnalysisRepository.update(
                db=db,
                analysis=existing,
                mime_type=mime_type,
                entropy=entropy,
                pe_analysis=pe_analysis,
                yara_matches=yara_matches,
                suspicious_strings=suspicious_strings,
            )

        else:

            AnalysisRepository.create(
                db=db,
                sample_id=sample_id,
                mime_type=mime_type,
                entropy=entropy,
                pe_analysis=pe_analysis,
                yara_matches=yara_matches,
                suspicious_strings=suspicious_strings,
            )

        return {
            "filename": file_path.name,
            "extension": extension,
            "mime_type": mime_type,
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
            "yara_matches": yara_matches,
            "suspicious_strings": suspicious_strings,
        }