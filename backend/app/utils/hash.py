
from pathlib import Path
import hashlib


def calculate_sha256(file_path: Path) -> str:
    """
    Calculate the SHA-256 hash of a file.

    The file is read in chunks so large uploaded files
    do not need to be loaded completely into memory.
    """

    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()

