from typing import Any


class RiskScoringService:
    """
    Deterministic risk scoring engine for static file analysis.

    The service does not execute files.

    Score range:
        0-19   -> LOW
        20-49  -> MEDIUM
        50-74  -> HIGH
        75-100 -> CRITICAL
    """

    @staticmethod
    def calculate_score(
        entropy: float,
        yara_matches: list[Any] | None = None,
        suspicious_strings: list[str] | None = None,
        pe_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        score = 0
        reasons: list[str] = []

        yara_matches = yara_matches or []
        suspicious_strings = suspicious_strings or []
        pe_analysis = pe_analysis or {}

        # ---------------------------------------------------------
        # Entropy
        # ---------------------------------------------------------

        if entropy >= 7.8:
            score += 20
            reasons.append("Very high file entropy")
        elif entropy >= 7.2:
            score += 10
            reasons.append("High file entropy")
        elif entropy >= 6.5:
            score += 5
            reasons.append("Moderately high file entropy")

        # ---------------------------------------------------------
        # YARA
        # ---------------------------------------------------------

        yara_count = len(yara_matches)

        if yara_count >= 5:
            score += 50
            reasons.append("Multiple ransomware YARA matches")
        elif yara_count >= 3:
            score += 40
            reasons.append("Several ransomware YARA matches")
        elif yara_count == 2:
            score += 30
            reasons.append("Two ransomware YARA matches")
        elif yara_count == 1:
            score += 25
            reasons.append("Ransomware YARA rule matched")

        # ---------------------------------------------------------
        # Suspicious strings
        # ---------------------------------------------------------

        string_count = len(suspicious_strings)

        if string_count >= 20:
            score += 20
            reasons.append("Many suspicious strings detected")
        elif string_count >= 10:
            score += 15
            reasons.append("Several suspicious strings detected")
        elif string_count >= 5:
            score += 10
            reasons.append("Multiple suspicious strings detected")
        elif string_count >= 1:
            score += 3
            reasons.append("Suspicious string detected")

        # ---------------------------------------------------------
        # PE analysis
        # ---------------------------------------------------------

        if pe_analysis:
            score += 5
            reasons.append("Portable Executable structure detected")

            suspicious_imports = pe_analysis.get(
                "suspicious_imports",
                [],
            )

            sections = pe_analysis.get(
                "sections",
                [],
            )

            if suspicious_imports:
                score += min(
                    len(suspicious_imports) * 5,
                    20,
                )

                reasons.append(
                    "Suspicious PE imports detected"
                )

            if isinstance(sections, list) and len(sections) > 10:
                score += 5
                reasons.append(
                    "Unusually large number of PE sections"
                )

        # ---------------------------------------------------------
        # Cap score
        # ---------------------------------------------------------

        score = min(
            max(score, 0),
            100,
        )

        # ---------------------------------------------------------
        # Severity
        # ---------------------------------------------------------

        if score >= 75:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 20:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons,
        }