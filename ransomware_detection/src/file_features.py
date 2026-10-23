
from pathlib import Path
import hashlib
import math


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
}


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    length = len(data)
    entropy = 0.0

    for count in counts:
        if count == 0:
            continue

        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_features(
    filename: str,
    data: bytes,
    yara_match_count: int = 0,
    threat_intelligence_score: float = 0.0,
) -> dict:
    extension = Path(filename).suffix.lower()

    return {
        "file_size": len(data),
        "entropy": calculate_entropy(data),
        "suspicious_extension": (
            1 if extension in SUSPICIOUS_EXTENSIONS else 0
        ),
        "yara_match_count": max(0, int(yara_match_count)),
        "threat_intelligence_score": float(
            threat_intelligence_score
        ),
        "sha256": calculate_sha256(data),
        "extension": extension,
    }
