from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


from src.data_loader import load_dataset


DATA_PATH = (
    "data/sample/sample_network_traffic.csv"
)

MODEL_PATH = Path("models/sample_model.joblib")


def train_model():
    # Load the artificial demonstration dataset.
    df = load_dataset(DATA_PATH)

    # Select the input features.
    feature_columns = [
        "duration",
        "protocol",
        "source_bytes",
        "destination_bytes",
        "connection_count",
    ]

    X = df[feature_columns]

    # Convert the labels into a binary classification target.
    # This is for the synthetic demonstration only.
    y = (
        df["label"] != "BENIGN"
    ).astype(int)

    numeric_features = [
        "duration",
        "source_bytes",
        "destination_bytes",
        "connection_count",
    ]

    categorical_features = [
        "protocol",
    ]

    # Preprocess numerical and categorical features.
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                "passthrough",
                numeric_features,
            ),
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_features,
            ),
        ]
    )

    # Build the machine learning pipeline.
    model = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                ),
            ),
        ]
    )

    # Train on all demonstration records.
    # This is a functional test, not a valid evaluation.
    model.fit(X, y)

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(model, MODEL_PATH)

    print("\nDemonstration model trained successfully!")

    print(f"Model saved to: {MODEL_PATH}")

    print(
        "\nWARNING: This model uses artificial data "
        "and is not a validated attack detector."
    )


if __name__ == "__main__":
    train_model()