from typing import Any


class DecryptionService:
    """
    Determines whether a file is eligible for ransomware
    decryption/recovery.

    This service does not perform cryptographic decryption yet.
    It only evaluates the analysis results and returns a
    structured decryption status.
    """

    @staticmethod
    def evaluate(
        ransomware_family: str | None = None,
        cipher_algorithm: str | None = None,
        threat_level: str | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate cryptographic feasibility.

        Returns a structured result that can later be used by
        the actual decryptor.
        """

        family = (
            ransomware_family.strip()
            if ransomware_family
            else None
        )

        cipher = (
            cipher_algorithm.strip()
            if cipher_algorithm
            else None
        )

        threat = (
            threat_level.strip().upper()
            if threat_level
            else None
        )

        # ---------------------------------------------------------
        # Benign / clean sample
        # ---------------------------------------------------------
        if family and family.lower() in {
            "benign",
            "benign / clean",
            "clean",
        }:
            return {
                "ransomware_family": family,
                "cipher_algorithm": None,
                "decryptor_available": False,
                "decryption_status": "NOT_APPLICABLE",
                "message": "No ransomware detected.",
            }

        # ---------------------------------------------------------
        # No ransomware family identified
        # ---------------------------------------------------------
        if not family:
            return {
                "ransomware_family": None,
                "cipher_algorithm": cipher,
                "decryptor_available": False,
                "decryption_status": "NOT_APPLICABLE",
                "message": "Ransomware family could not be identified.",
            }

        # ---------------------------------------------------------
        # No encryption information
        # ---------------------------------------------------------
        if not cipher or cipher.lower() in {
            "none",
            "unknown",
            "n/a",
        }:
            return {
                "ransomware_family": family,
                "cipher_algorithm": None,
                "decryptor_available": False,
                "decryption_status": "UNSUPPORTED",
                "message": (
                    "No supported cipher information is available "
                    "for this ransomware family."
                ),
            }

        # ---------------------------------------------------------
        # Ransomware identified but decryptor not implemented yet
        # ---------------------------------------------------------
        return {
            "ransomware_family": family,
            "cipher_algorithm": cipher,
            "decryptor_available": False,
            "decryption_status": "DECRYPTOR_NOT_IMPLEMENTED",
            "message": (
                "Ransomware and encryption information were identified, "
                "but a compatible decryptor has not been implemented."
            ),
        }