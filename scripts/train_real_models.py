from pathlib import Path
import json
import warnings

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore", category=RuntimeWarning)

DATA_DIR = Path("data/raw")
OUTPUT_DIR = Path("outputs/metrics")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLES_PER_FILE = 20_000
RANDOM_STATE = 42
LABEL_COLUMN = "Label"


def load_bounded_sample(file_path: Path) -> pd.DataFrame:
    """Read a bounded random sample from one CSV using chunked loading."""
    chunks = []
    remaining = SAMPLES_PER_FILE

    for chunk in pd.read_csv(file_path, chunksize=10_000, low_memory=False):
        chunk.columns = chunk.columns.astype(str).str.strip()

        if LABEL_COLUMN not in chunk.columns:
            raise ValueError(
                f"'{LABEL_COLUMN}' column not found in {file_path.name}"
            )

        # Randomly retain only part of each chunk.
        if len(chunk) > remaining:
            chunk = chunk.sample(
                n=remaining,
                random_state=RANDOM_STATE,
            )

        chunks.append(chunk)
        remaining -= len(chunk)

        if remaining <= 0:
            break

    if not chunks:
        return pd.DataFrame()

    return pd.concat(chunks, ignore_index=True)


def main() -> None:
    csv_files = sorted(DATA_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR.resolve()}")

    print(f"Found {len(csv_files)} CSV files.")

    sampled_frames = []

    for file_path in csv_files:
        print(f"\nSampling: {file_path.name}")
        frame = load_bounded_sample(file_path)

        if not frame.empty:
            frame["source_file"] = file_path.name
            sampled_frames.append(frame)
            print(f"Rows retained: {len(frame):,}")

    data = pd.concat(sampled_frames, ignore_index=True)

    data.columns = data.columns.astype(str).str.strip()
    data[LABEL_COLUMN] = data[LABEL_COLUMN].astype(str).str.strip()

    # Drop records with missing labels.
    data = data.dropna(subset=[LABEL_COLUMN])
    data = data[data[LABEL_COLUMN] != ""]

    print(f"\nTotal sampled rows: {len(data):,}")
    print("\nSampled label distribution:")
    print(data[LABEL_COLUMN].value_counts().to_string())

    # Keep source_file for audit purposes, but never use it as a feature.
    excluded = {LABEL_COLUMN, "source_file"}
    feature_columns = [
        column for column in data.columns if column not in excluded
    ]

    X = data[feature_columns].copy()
    y = data[LABEL_COLUMN].copy()

    # CICIDS2017 flow features should be numeric. Convert invalid values to NaN.
    for column in X.columns:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    # Remove columns that have no usable numeric values.
    X = X.dropna(axis=1, how="all")

    # Replace infinite values with NaN; imputation happens inside the pipeline.
    X = X.replace([np.inf, -np.inf], np.nan)

    # Binary target: BENIGN vs. all other labelled traffic.
    y_binary = y.map(
        lambda label: "BENIGN"
        if label.strip().upper() == "BENIGN"
        else "POTENTIAL_ATTACK"
    )

    if y_binary.nunique() < 2:
        raise ValueError(
            "The sampled data contains fewer than two target classes. "
            "Inspect the dataset labels before training."
        )

    print(f"\nFeatures retained: {X.shape[1]}")

    # Stratification preserves class proportions in this random holdout.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_binary,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=y_binary,
    )

    models = {
        "logistic_regression": Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=1000,
                        class_weight="balanced",
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
        "random_forest": Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    RandomForestClassifier(
                        n_estimators=100,
                        max_depth=20,
                        min_samples_leaf=2,
                        class_weight="balanced_subsample",
                        random_state=RANDOM_STATE,
                        n_jobs=-1,
                    ),
                ),
            ]
        ),
    }

    results = {
        "experiment": "CICIDS2017 bounded per-file sample",
        "sampled_rows": int(len(data)),
        "features": int(X.shape[1]),
        "test_size": 0.25,
        "random_state": RANDOM_STATE,
        "warning": (
            "Prototype random holdout on sampled data. "
            "Not a full-dataset or time/group-independent benchmark."
        ),
        "models": {},
    }

    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train, y_train)

        predictions = model.predict(X_test)

        # The positive class is POTENTIAL_ATTACK.
        tn, fp, fn, tp = confusion_matrix(
            y_test,
            predictions,
            labels=["BENIGN", "POTENTIAL_ATTACK"],
        ).ravel()

        false_positive_rate = (
            float(fp / (fp + tn)) if (fp + tn) > 0 else None
        )

        metrics = {
            "accuracy": float(accuracy_score(y_test, predictions)),
            "precision": float(
                precision_score(
                    y_test,
                    predictions,
                    pos_label="POTENTIAL_ATTACK",
                    zero_division=0,
                )
            ),
            "recall": float(
                recall_score(
                    y_test,
                    predictions,
                    pos_label="POTENTIAL_ATTACK",
                    zero_division=0,
                )
            ),
            "f1_score": float(
                f1_score(
                    y_test,
                    predictions,
                    pos_label="POTENTIAL_ATTACK",
                    zero_division=0,
                )
            ),
            "false_positive_rate": false_positive_rate,
            "confusion_matrix": {
                "labels": ["BENIGN", "POTENTIAL_ATTACK"],
                "values": [[int(tn), int(fp)], [int(fn), int(tp)]],
            },
            "classification_report": classification_report(
                y_test,
                predictions,
                labels=["BENIGN", "POTENTIAL_ATTACK"],
                zero_division=0,
                output_dict=True,
            ),
        }

        results["models"][name] = metrics

        print(f"\n{name} results:")
        print(f"Accuracy:           {metrics['accuracy']:.4f}")
        print(f"Precision:          {metrics['precision']:.4f}")
        print(f"Recall:             {metrics['recall']:.4f}")
        print(f"F1-score:           {metrics['f1_score']:.4f}")
        print(f"False-positive rate: {false_positive_rate}")

        model_path = OUTPUT_DIR / f"{name}_prototype.joblib"

        # These are prototype models, not production-ready artifacts.
        import joblib
        joblib.dump(
            {
                "model": model,
                "feature_columns": list(X.columns),
                "target_type": "BENIGN_vs_POTENTIAL_ATTACK",
                "experiment": results["experiment"],
            },
            model_path,
        )

    results_path = OUTPUT_DIR / "prototype_model_metrics.json"

    with results_path.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)

    print(f"\nMetrics saved to: {results_path}")
    print("Prototype training completed.")


if __name__ == "__main__":
    main()