from typing import Any


class RansomwareIdentificationService:
    """
    Identifies a probable ransomware family and cipher algorithm
    from static-analysis indicators.

    This service does not execute files and does not decrypt files.
    """

    @staticmethod
    def identify(
        yara_matches: list[Any] | None = None,
        suspicious_strings: list[str] | None = None,
        pe_analysis: dict[str, Any] | None = None,
        risk_score: int = 0,
        severity: str = "LOW",
    ) -> dict[str, Any]:

        yara_matches = yara_matches or []
        suspicious_strings = suspicious_strings or []
        pe_analysis = pe_analysis or {}

        normalized_strings = {
            str(value).strip().lower()
            for value in suspicious_strings
        }

        normalized_yara = {
            str(value).strip().lower()
            for value in yara_matches
        }

        severity = str(severity).strip().upper()

        # ---------------------------------------------------------
        # Demo / clean sample detection
        # ---------------------------------------------------------

        demo_indicators = {
            "test_ransom_note",
            "simulated_encryption",
            "demo_decryption",
        }

        only_demo_indicators = (
            normalized_strings
            and normalized_strings.issubset(demo_indicators)
        )

        if (
            only_demo_indicators
            and not normalized_yara
            and not pe_analysis
            and risk_score < 20
            and severity == "LOW"
        ):
            return {
                "ransomware_family": "Benign / Clean",
                "cipher_algorithm": "None",
                "confidence": 0.96,
                "identification_status": "BENIGN",
                "reason": (
                    "Only simulated/demo indicators were detected; "
                    "no strong ransomware indicators were found."
                ),
            }

        # ---------------------------------------------------------
        # Strong ransomware indicators
        # ---------------------------------------------------------

        if normalized_yara or risk_score >= 50:
            return {
                "ransomware_family": "Unknown",
                "cipher_algorithm": "Unknown",
                "confidence": 0.50,
                "identification_status": "UNKNOWN_RANSOMWARE",
                "reason": (
                    "Strong ransomware-like indicators were detected, "
                    "but the available evidence is insufficient to "
                    "identify a specific family or cipher."
                ),
            }

        # ---------------------------------------------------------
        # Suspicious sample
        # ---------------------------------------------------------

        if (
            suspicious_strings
            or severity in {"MEDIUM", "HIGH", "CRITICAL"}
            or risk_score >= 20
        ):
            return {
                "ransomware_family": "Unknown",
                "cipher_algorithm": "Unknown",
                "confidence": 0.30,
                "identification_status": "SUSPICIOUS",
                "reason": (
                    "Suspicious indicators were detected, but there "
                    "is insufficient evidence to identify a specific "
                    "ransomware family or cipher."
                ),
            }

        # ---------------------------------------------------------
        # No significant indicators
        # ---------------------------------------------------------

        return {
            "ransomware_family": "Benign / Clean",
            "cipher_algorithm": "None",
            "confidence": 0.90,
            "identification_status": "BENIGN",
            "reason": (
                "No significant ransomware indicators were detected."
            ),
        }