from pathlib import Path
from datetime import datetime, timezone
import mimetypes
import math

from app.utils.hash import calculate_sha256


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
    def analyze(file_path: Path) -> dict:
        """
        Perform basic static analysis.
        """

        if not file_path.exists():
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        stat = file_path.stat()

        extension = file_path.suffix.lower().lstrip(".")

        mime_type, _ = mimetypes.guess_type(
            file_path.name
        )

        sha256 = calculate_sha256(file_path)

        entropy = AnalysisServices.calculate_entropy(
            file_path
        )

        return {
            "filename": file_path.name,
            "extension": extension,
            "mime_type": mime_type or "application/octet-stream",
            "file_size": stat.st_size,
            "sha256": sha256,
            "entropy": entropy,
            "created_at": datetime.fromtimestamp(
                stat.st_ctime,
                tz=timezone.utc
            ).isoformat(),
            "modified_at": datetime.fromtimestamp(
                stat.st_mtime,
                tz=timezone.utc
            ).isoformat(),
        }