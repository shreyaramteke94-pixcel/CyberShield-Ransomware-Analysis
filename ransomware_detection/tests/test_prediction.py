from src.predict import RansomwarePredictor


predictor = RansomwarePredictor()


print("\n==============================")
print("ML PREDICTION TEST")
print("==============================")


# Completely synthetic feature values.

test_features = {

    "file_size": 250000,

    "entropy": 7.8,

    "suspicious_extension": 1,

    "yara_match_count": 2,

    "threat_intelligence_score": 0.90
}


result = predictor.predict(
    test_features
)


print(
    "\nPrediction:",
    result["prediction"]
)


print(
    "Risk probability:",
    f"{result['risk_probability']:.2%}"
)


if result["prediction"] == 1:

    print(
        "\nResult: HIGHER RISK"
    )

else:

    print(
        "\nResult: LOWER RISK"
    )


print("==============================")