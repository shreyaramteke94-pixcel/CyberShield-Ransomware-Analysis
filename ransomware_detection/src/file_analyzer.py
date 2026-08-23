import os
import hashlib
import mimetypes

from src.entropy import calculate_entropy


def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(8192)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def analyze_file(file_path):

    if not os.path.exists(file_path):

        raise FileNotFoundError(
            "File does not exist."
        )

    file_name = os.path.basename(
        file_path
    )

    file_size = os.path.getsize(
        file_path
    )

    extension = os.path.splitext(
        file_name
    )[1].lower()

    mime_type, _ = mimetypes.guess_type(
        file_path
    )

    sha256 = calculate_sha256(
        file_path
    )

    entropy = calculate_entropy(
        file_path
    )

    return {
        "file_name": file_name,
        "file_size": file_size,
        "extension": extension,
        "mime_type": mime_type,
        "sha256": sha256,
        "entropy": entropy
    }