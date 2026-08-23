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

        entropy -= (
            probability
            * math.log2(probability)
        )

    return entropy


def calculate_sha256(data: bytes) -> str:

    return hashlib.sha256(data).hexdigest()


def extract_features(
    filename: str,
    data: bytes
) -> dict:

    extension = (
        Path(filename)
        .suffix
        .lower()
    )

    entropy = calculate_entropy(data)

    sha256 = calculate_sha256(data)

    suspicious_extension = (
        1
        if extension in SUSPICIOUS_EXTENSIONS
        else 0
    )

    # Module 8 keeps these offline.
    yara_match_count = 0

    threat_intelligence_score = 0.0

    return {
        "file_size": len(data),

        "entropy": entropy,

        "suspicious_extension":
            suspicious_extension,

        "yara_match_count":
            yara_match_count,

        "threat_intelligence_score":
            threat_intelligence_score,

        "sha256": sha256,

        "extension": extension,
    }