from pathlib import Path
from datetime import datetime, timezone

import math
import mimetypes

from sqlalchemy.orm import Session

from app.repositories.analysis_repository import AnalysisRepository
from app.utils.hash import calculate_sha256
from app.utils.pe_parser import PEParser
from app.utils.yara_scanner import YaraScanner
from app.utils.string_extractor import StringExtractor
from app.utils.risk_scoring import RiskScoringService


class AnalysisServices:
    """
    Performs safe static analysis on uploaded files.

    The service does not execute uploaded files.
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
        """
        Perform complete static analysis and save the results.
        """

        # ---------------------------------------------------------
        # Check file
        # ---------------------------------------------------------

        if not file_path.exists():
            raise FileNotFoundError(
                f"{file_path} does not exist."
            )

        # ---------------------------------------------------------
        # Basic file information
        # ---------------------------------------------------------

        stat = file_path.stat()

        extension = (
            file_path.suffix
            .lower()
            .replace(".", "")
        )

        mime_type, _ = mimetypes.guess_type(
            file_path.name
        )

        mime_type = (
            mime_type
            or "application/octet-stream"
        )

        # ---------------------------------------------------------
        # SHA-256
        # ---------------------------------------------------------

        sha256 = calculate_sha256(
            file_path
        )

        # ---------------------------------------------------------
        # Entropy
        # ---------------------------------------------------------

        entropy = AnalysisServices.calculate_entropy(
            file_path
        )

        # ---------------------------------------------------------
        # PE Analysis
        # ---------------------------------------------------------

        pe_analysis = None

        if extension in [
            "exe",
            "dll",
            "sys",
            "scr",
        ]:
            try:
                pe_analysis = PEParser.parse(
                    file_path
                )
            except Exception:
                pe_analysis = None

        # ---------------------------------------------------------
        # YARA Scan
        # ---------------------------------------------------------

        try:
            yara_matches = YaraScanner.scan(
                file_path
            )
        except Exception:
            yara_matches = []

        # ---------------------------------------------------------
        # String Extraction
        # ---------------------------------------------------------

        try:
            all_strings = StringExtractor.extract(
                file_path
            )

            suspicious_strings = (
                StringExtractor.suspicious_strings(
                    all_strings
                )
            )

        except Exception:
            suspicious_strings = []

        # ---------------------------------------------------------
        # Risk Scoring
        # ---------------------------------------------------------

        risk_result = (
            RiskScoringService.calculate_score(
                entropy=entropy,
                yara_matches=yara_matches,
                suspicious_strings=suspicious_strings,
                pe_analysis=pe_analysis,
            )
        )

        risk_score = risk_result.get(
            "risk_score",
            0,
        )

        severity = risk_result.get(
            "severity",
            "LOW",
        )

        risk_reasons = risk_result.get(
            "reasons",
            [],
        )

        # ---------------------------------------------------------
        # Save Analysis
        # ---------------------------------------------------------

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
                risk_score=risk_score,
                severity=severity,
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
                risk_score=risk_score,
                severity=severity,
            )

        # ---------------------------------------------------------
        # Return Complete Analysis
        # ---------------------------------------------------------

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

            "risk_score": risk_score,

            "severity": severity,

            "reasons": risk_reasons,
        }