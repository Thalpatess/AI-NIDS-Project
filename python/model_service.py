from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "packet_count",
    "fwd_payload_entropy",
    "bwd_payload_entropy",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_rst_count",
    "tcp_fin_count",
    "idle_max",
    "inter_arrival_mean",
    "flow_size",
]

MODEL_PATH = Path(__file__).resolve().parent / "models" / "nids_isolation_forest.joblib"


def predict_vector(features: dict) -> dict:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Train it first with python/train_model.py")

    model = joblib.load(MODEL_PATH)
    vector = np.array([float(features.get(col, 0.0)) for col in FEATURE_COLUMNS], dtype=float).reshape(1, -1)
    score = float(model.score_samples(vector)[0])
    prediction = int(model.predict(vector)[0])
    anomaly = prediction == -1

    return {
        "anomaly": anomaly,
        "score": score,
        "prediction": prediction,
    }


def load_flow_csv(csv_path: str) -> pd.DataFrame:
    return pd.read_csv(csv_path)


if __name__ == "__main__":
    sample = {
        "flow_duration": 0.24,
        "packet_rate": 15.0,
        "byte_rate": 6100.0,
        "packet_count": 10,
        "fwd_payload_entropy": 4.2,
        "bwd_payload_entropy": 3.9,
        "tcp_syn_count": 1,
        "tcp_ack_count": 8,
        "tcp_rst_count": 0,
        "tcp_fin_count": 0,
        "idle_max": 0.05,
        "inter_arrival_mean": 0.02,
        "flow_size": 1500,
    }
    print(json.dumps(predict_vector(sample), indent=2))
