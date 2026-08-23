from dataclasses import dataclass


@dataclass
class RiskResult:

    score: float
    level: str
    reasons: list[str]


class RiskEngine:

    def calculate(
        self,
        ml_probability: float,
        entropy: float,
        yara_match_count: int,
        suspicious_extension: int,
        threat_intelligence_score: float
    ) -> RiskResult:

        reasons = []

        # --------------------------------
        # 1. ML contribution
        # --------------------------------

        ml_score = ml_probability * 50

        if ml_probability >= 0.70:

            reasons.append(
                "ML model indicates elevated risk."
            )


        # --------------------------------
        # 2. Entropy contribution
        # --------------------------------

        entropy_score = 0

        if entropy >= 7.5:

            entropy_score = 20

            reasons.append(
                "Very high file entropy detected."
            )

        elif entropy >= 7.0:

            entropy_score = 15

            reasons.append(
                "High file entropy detected."
            )

        elif entropy >= 6.5:

            entropy_score = 8


        # --------------------------------
        # 3. YARA contribution
        # --------------------------------

        yara_score = min(
            yara_match_count * 10,
            20
        )

        if yara_match_count > 0:

            reasons.append(
                f"{yara_match_count} YARA "
                "match(es) detected."
            )


        # --------------------------------
        # 4. Extension contribution
        # --------------------------------

        extension_score = 0

        if suspicious_extension:

            extension_score = 10

            reasons.append(
                "Suspicious file extension detected."
            )


        # --------------------------------
        # 5. Threat intelligence
        # --------------------------------

        ti_score = (
            threat_intelligence_score * 20
        )

        if threat_intelligence_score >= 0.70:

            reasons.append(
                "Threat-intelligence indicator "
                "has high confidence."
            )


        # --------------------------------
        # Final score
        # --------------------------------

        total_score = (
            ml_score
            + entropy_score
            + yara_score
            + extension_score
            + ti_score
        )


        # Never exceed 100.

        total_score = min(
            total_score,
            100
        )


        # --------------------------------
        # Risk level
        # --------------------------------

        if total_score >= 70:

            level = "HIGH"

        elif total_score >= 40:

            level = "MEDIUM"

        else:

            level = "LOW"


        if not reasons:

            reasons.append(
                "No strong suspicious indicators detected."
            )


        return RiskResult(
            score=round(
                total_score,
                2
            ),
            level=level,
            reasons=reasons
        )