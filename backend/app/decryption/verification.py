"""
Output integrity verifier for the CyberShield Decryption & Recovery Engine.

This module provides verification functions that are called AFTER a recovery
operation completes but BEFORE RECOVERY_SUCCEEDED is reported to the caller.

Verification strategy
---------------------
  Demo jobs  — SHA-256 of the recovered output file is compared against the
               expected hash embedded in the encrypted blob's header.
               Additionally, the output is read back from disk (not from the
               in-memory buffer) to confirm the file was written correctly.

  Real jobs  — Placeholder; real adapters should provide their own
               verification method (e.g., format magic check, vendor hash).

A job MUST NOT be marked RECOVERY_SUCCEEDED if verify_demo_output() returns
False.  The job must instead be marked OUTPUT_VERIFICATION_FAILED.
"""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Demo output verification
# ---------------------------------------------------------------------------


def verify_demo_output(output_path: Path, expected_sha256_hex: str) -> bool:
    """
    Read the recovered file from disk and verify its SHA-256.

    Parameters
    ----------
    output_path : Path
        Absolute path to the recovered (decrypted) output file.
    expected_sha256_hex : str
        Hex-encoded expected SHA-256 of the original plaintext,
        extracted from the encrypted blob's header.

    Returns
    -------
    bool
        True  — output file exists, is readable, and its SHA-256
                matches *expected_sha256_hex*.
        False — file is missing, unreadable, or hash does not match
                (reason logged at WARNING level).
    """
    if not output_path.is_file():
        logger.warning(
            "Verification failed: output file does not exist: %s",
            output_path,
        )
        return False

    actual_hex = _sha256_hex_of_file(output_path)
    if actual_hex is None:
        logger.warning(
            "Verification failed: could not read output file: %s",
            output_path,
        )
        return False

    import hmac
    match = hmac.compare_digest(actual_hex.lower(), expected_sha256_hex.lower())

    if match:
        logger.info(
            "Output verification PASSED for %s (SHA-256: %s)",
            output_path.name,
            actual_hex[:16] + "...",
        )
    else:
        logger.warning(
            "Output verification FAILED for %s — "
            "expected SHA-256 %s, got %s",
            output_path.name,
            expected_sha256_hex[:16] + "...",
            actual_hex[:16] + "...",
        )

    return match


def compute_file_sha256(file_path: Path) -> str | None:
    """
    Compute the hex SHA-256 of a file, or None if it cannot be read.
    Reusable helper for other parts of the module.
    """
    return _sha256_hex_of_file(file_path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_hex_of_file(path: Path) -> str | None:
    """Read *path* in chunks and return its hex SHA-256, or None on error."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        logger.error("Failed to read %s for verification: %s", path, exc)
        return None
