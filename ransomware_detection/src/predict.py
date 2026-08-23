import joblib
import pandas as pd


MODEL_PATH = (
    "models/ransomware_model.joblib"
)


class RansomwarePredictor:

    def __init__(
        self,
        model_path=MODEL_PATH
    ):

        bundle = joblib.load(
            model_path
        )

        self.model = bundle["model"]

        self.features = bundle[
            "features"
        ]


    def predict(
        self,
        feature_data
    ):

        dataframe = pd.DataFrame(
            [feature_data],
            columns=self.features
        )


        prediction = self.model.predict(
            dataframe
        )[0]


        probabilities = (
            self.model.predict_proba(
                dataframe
            )[0]
        )


        risk_probability = (
            probabilities[1]
        )


        return {
            "prediction": int(
                prediction
            ),

            "risk_probability":
                float(
                    risk_probability
                )
        }