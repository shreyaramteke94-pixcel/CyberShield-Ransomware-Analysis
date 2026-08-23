import os

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split


DATASET = "data/ml_dataset.csv"

MODEL_OUTPUT = "models/ransomware_model.joblib"


FEATURE_COLUMNS = [
    "file_size",
    "entropy",
    "suspicious_extension",
    "yara_match_count",
    "threat_intelligence_score"
]


TARGET_COLUMN = "label"


def main():

    print("\n==============================")
    print("MODEL TRAINING")
    print("==============================")


    if not os.path.exists(DATASET):

        raise FileNotFoundError(
            f"Dataset not found: {DATASET}"
        )


    # Load dataset.

    data = pd.read_csv(
        DATASET
    )


    print(
        f"Loaded {len(data)} samples."
    )


    # Separate features and labels.

    X = data[
        FEATURE_COLUMNS
    ]

    y = data[
        TARGET_COLUMN
    ]


    # Split into training and testing data.

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y
        )
    )


    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples: {len(X_test)}"
    )


    # Create the model.

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )


    # Train.

    print("\nTraining model...")

    model.fit(
        X_train,
        y_train
    )


    # Evaluate.

    predictions = model.predict(
        X_test
    )


    accuracy = accuracy_score(
        y_test,
        predictions
    )


    print(
        f"\nAccuracy: {accuracy:.4f}"
    )


    print("\nClassification report:")

    print(
        classification_report(
            y_test,
            predictions
        )
    )


    print("Confusion matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )


    # Save model.

    os.makedirs(
        "models",
        exist_ok=True
    )


    joblib.dump(
        {
            "model": model,
            "features": FEATURE_COLUMNS
        },
        MODEL_OUTPUT
    )


    print(
        f"\nModel saved to: {MODEL_OUTPUT}"
    )


    print("==============================\n")


if __name__ == "__main__":

    main()