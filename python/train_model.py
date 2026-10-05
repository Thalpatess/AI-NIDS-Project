#!/usr/bin/env python3

import pandas as pd
from sklearn.ensemble import IsolationForest
from pathlib import Path
import joblib

DATA_PATH = Path(__file__).resolve().parent / "data" / "network_flows.csv"
MODEL_PATH = Path(__file__).resolve().parent / "models" / "anomaly_model.pkl"

def train_model():
    print("Loading network flow data...")
    df = pd.read_csv(DATA_PATH)
    
    # Feature columns (all except label)
    features = [col for col in df.columns if col != 'label']
    X = df[features]
    
    print(f"Training Isolation Forest on {len(X)} samples...")
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    
    # Save model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    
    # Calculate anomaly scores
    scores = model.decision_function(X)
    predictions = model.predict(X)
    
    anomalies = sum(predictions == -1)
    print(f"Detected {anomalies} anomalies out of {len(predictions)} flows")
    print(f"Mean anomaly score: {scores.mean():.3f}")
    print(f"Std dev: {scores.std():.3f}")

if __name__ == "__main__":
    train_model()
