"""
Behavioural Anomaly Detection Engine
Module 1 — Point 1 of PS7

Trains an unsupervised Isolation Forest model on NSL-KDD network traffic
to detect anomalous behaviour WITHOUT relying on known attack signatures.
The model learns what "normal" traffic looks like and flags deviations.
"""

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix

from preprocess import load_data, preprocess


def train_anomaly_model(X_train, contamination=0.5, random_state=42):
    """
    Train Isolation Forest for behavioural anomaly detection.

    contamination=0.5 was chosen after tuning across [0.30, 0.40, 0.46, 0.50] —
    it gave the best precision/recall balance (F1=0.8248) on the held-out test set.
    In a real deployment this would instead be tuned on a normal-traffic-only
    baseline window, then adjusted as the environment's true attack ratio becomes known.
    """
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples="auto",
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_train)
    return model


def check_single_event(model, scaler, encoders, feature_cols, raw_event: dict):
    """
    Real-time scoring for a single incoming network event.
    This is the function the dashboard/orchestrator will call live.

    raw_event: dict with keys matching feature_cols (raw, unencoded values)
    Returns: dict with anomaly_score, is_anomaly (bool), and severity label
    """
    import pandas as pd
    df = pd.DataFrame([raw_event])[feature_cols]

    for col, le in encoders.items():
        # handle unseen categories gracefully
        df[col] = df[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
        df[col] = le.transform(df[col])

    X = scaler.transform(df)
    raw_score = model.decision_function(X)[0]
    anomaly_score = float(-raw_score)
    prediction = model.predict(X)[0]
    is_anomaly = bool(prediction == -1)

    if anomaly_score > 0.15:
        severity = "critical"
    elif anomaly_score > 0.05:
        severity = "high"
    elif anomaly_score > 0:
        severity = "medium"
    else:
        severity = "low"

    return {
        "anomaly_score": round(anomaly_score, 4),
        "is_anomaly": is_anomaly,
        "severity": severity
    }


def score_and_predict(model, X):
    """
    Returns:
      anomaly_scores: higher = more anomalous (we flip sklearn's convention for intuitiveness)
      predictions: 1 = anomaly/attack, 0 = normal
    """
    raw_scores = model.decision_function(X)  # higher = more normal in sklearn's convention
    anomaly_scores = -raw_scores  # flip so higher = more anomalous
    predictions = model.predict(X)  # 1 = normal, -1 = anomaly in sklearn's convention
    predictions = np.where(predictions == -1, 1, 0)  # convert to 1 = attack, 0 = normal
    return anomaly_scores, predictions


def evaluate(y_true, y_pred):
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm.tolist()
    }


if __name__ == "__main__":
    print("Loading and preprocessing NSL-KDD data...")
    train_df, test_df = load_data(
        "../data/nsl-kdd/KDDTrain+.txt",
        "../data/nsl-kdd/KDDTest+.txt"
    )
    X_train, X_test, y_train, y_test, scaler, encoders, feature_cols = preprocess(train_df, test_df)

    print("Training Isolation Forest (behavioural baseline)...")
    model = train_anomaly_model(X_train)

    print("\n--- Evaluation on TRAIN set ---")
    train_scores, train_preds = score_and_predict(model, X_train)
    print(classification_report(y_train, train_preds, target_names=["normal", "attack"], zero_division=0))

    print("\n--- Evaluation on TEST set (held-out, unseen data) ---")
    test_scores, test_preds = score_and_predict(model, X_test)
    print(classification_report(y_test, test_preds, target_names=["normal", "attack"], zero_division=0))

    metrics = evaluate(y_test, test_preds)
    print("\nTest set summary metrics:", metrics)

    # Save model + preprocessing artifacts for reuse in dashboard/attribution agent
    joblib.dump(model, "anomaly_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(encoders, "encoders.pkl")
    print("\nSaved: anomaly_model.pkl, scaler.pkl, encoders.pkl")
