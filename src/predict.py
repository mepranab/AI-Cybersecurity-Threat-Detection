from pathlib import Path

import joblib
import pandas as pd


MODEL_PATH = Path(
    "models/sample_model.joblib"
)


def predict_traffic(
    duration: float,
    protocol: str,
    source_bytes: int,
    destination_bytes: int,
    connection_count: int,
) -> dict:

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Model not found. Run the training script first."
        )

    model = joblib.load(MODEL_PATH)

    traffic = pd.DataFrame(
        [
            {
                "duration": duration,
                "protocol": protocol,
                "source_bytes": source_bytes,
                "destination_bytes": destination_bytes,
                "connection_count": connection_count,
            }
        ]
    )

    prediction = int(
        model.predict(traffic)[0]
    )

    probability = model.predict_proba(
        traffic
    )[0]

    suspicious_probability = float(
        probability[1]
    )

    if prediction == 1:
        result = "SUSPICIOUS_SIMULATED"
    else:
        result = "BENIGN_PREDICTION"

    return {
        "result": result,
        "suspicious_probability": round(
            suspicious_probability,
            4,
        ),
        "notice": (
            "Demonstration only: trained on artificial data."
        ),
    }


if __name__ == "__main__":

    result = predict_traffic(
        duration=12.0,
        protocol="TCP",
        source_bytes=80000,
        destination_bytes=200,
        connection_count=150,
    )

    print("\nPrediction result:")
    print(result)