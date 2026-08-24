from pathlib import Path

import joblib


class RansomwarePredictor:
    """
    Loads the ransomware ML model and performs predictions.
    """

    def __init__(self):

        # Project structure:
        #
        # CyberShield-Ransomware-Analysis/
        # ├── ransomware_detection/
        # │   ├── models/
        # │   │   └── ransomware_model.joblib
        # │   └── src/
        # │       └── predict.py
        #
        # __file__ = ransomware_detection/src/predict.py
        #
        # parents[1] = ransomware_detection/

        project_dir = (
            Path(__file__).resolve().parents[1]
        )

        model_path = (
            project_dir
            / "models"
            / "ransomware_model.joblib"
        )

        if not model_path.exists():
            raise FileNotFoundError(
                f"Ransomware model not found: {model_path}"
            )

        bundle = joblib.load(model_path)

        # Support either a saved model directly
        # or a dictionary containing the model.

        if isinstance(bundle, dict):

            self.model = bundle.get(
                "model",
                bundle.get("classifier")
            )

            if self.model is None:
                raise ValueError(
                    "The model bundle does not contain "
                    "'model' or 'classifier'."
                )

        else:

            self.model = bundle

    def predict(self, features):
        """
        Predict ransomware probability from extracted features.
        """

        feature_values = [
            features["file_size"],
            features["entropy"],
            features["suspicious_extension"],
            features["yara_match_count"],
            features["threat_intelligence_score"],
        ]

        probability = self.model.predict_proba(
            [feature_values]
        )[0][1]

        prediction = (
            "ransomware"
            if probability >= 0.5
            else "benign"
        )

        return {
            "prediction": prediction,
            "risk_probability": float(probability),
        }