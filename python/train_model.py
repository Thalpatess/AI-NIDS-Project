import os
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score
import joblib
import numpy as np
import pandas as pd

DATASET_PATH = Path(__file__).resolve().parent / "data" / "network_flows.csv"
MODEL_PATH = Path(__file__).resolve().parent / "models" / "nids_isolation_forest.joblib"
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


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found at {path}. Generate a sample CSV or provide a real dataset.")
    df = pd.read_csv(path)
    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    return df


def train_model(df: pd.DataFrame) -> IsolationForest:
    X = df[FEATURE_COLUMNS].fillna(0).astype(float)
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)

    preds = model.predict(X_test)
    labels = np.where(preds == -1, 1, 0)
    y_true = np.zeros(len(X_test), dtype=int)

    precision = precision_score(y_true, labels, zero_division=0)
    recall = recall_score(y_true, labels, zero_division=0)
    f1 = f1_score(y_true, labels, zero_division=0)
    print(f"Model metrics: precision={precision:.4f}, recall={recall:.4f}, f1={f1:.4f}")

    return model


def save_model(model: IsolationForest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    print(f"Saved model to {path}")


def main() -> None:
    df = load_dataset(DATASET_PATH)
    model = train_model(df)
    save_model(model, MODEL_PATH)


if __name__ == "__main__":
    main()
