from src.predict import RansomwarePredictor
from src.risk_engine import RiskEngine


class Analyzer:

    def __init__(self):

        self.predictor = (
            RansomwarePredictor()
        )

        self.risk_engine = (
            RiskEngine()
        )


    def analyze(
        self,
        features
    ):

        # -----------------------------
        # ML prediction
        # -----------------------------

        prediction = (
            self.predictor.predict(
                features
            )
        )


        # -----------------------------
        # Final risk engine
        # -----------------------------

        result = (
            self.risk_engine.calculate(

                ml_probability=(
                    prediction[
                        "risk_probability"
                    ]
                ),

                entropy=features[
                    "entropy"
                ],

                yara_match_count=features[
                    "yara_match_count"
                ],

                suspicious_extension=features[
                    "suspicious_extension"
                ],

                threat_intelligence_score=(
                    features[
                        "threat_intelligence_score"
                    ]
                )
            )
        )


        return {

            "ml_prediction":
                prediction[
                    "prediction"
                ],

            "ml_probability":
                prediction[
                    "risk_probability"
                ],

            "risk_score":
                result.score,

            "risk_level":
                result.level,

            "reasons":
                result.reasons
        }