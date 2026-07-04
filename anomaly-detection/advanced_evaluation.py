"""
Advanced Behavioural Anomaly Detection — Deep Evaluation
Module 1 — Point 1 of PS7

Improvements over baseline:
1. TRUE anomaly detection methodology: trains ONLY on normal traffic
   (not a mix of normal+attack), so the model genuinely learns a
   "normal behaviour baseline" rather than being tuned to a known attack ratio.
2. Compares two algorithms: Isolation Forest vs Local Outlier Factor (novelty mode)
3. Per-attack-category breakdown (DoS, Probe, R2L, U2R) — not just overall accuracy
4. Feature importance via permutation on anomaly score
5. Visualizations for the report/deck: confusion matrix, PR curve, feature importance
"""

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import (
    classification_report, precision_recall_fscore_support,
    confusion_matrix, precision_recall_curve, auc
)

from preprocess import load_data, preprocess, COLUMN_NAMES

# NSL-KDD attack category mapping (standard grouping used in NSL-KDD research)
ATTACK_CATEGORIES = {
    "normal": "normal",
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "apache2": "DoS", "udpstorm": "DoS", "processtable": "DoS", "worm": "DoS", "mailbomb": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L", "phf": "R2L",
    "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L", "sendmail": "R2L", "named": "R2L",
    "snmpgetattack": "R2L", "snmpguess": "R2L", "xlock": "R2L", "xsnoop": "R2L", "httptunnel": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
    "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R"
}


def get_attack_category(label):
    return ATTACK_CATEGORIES.get(label, "Unknown")


def train_on_normal_only(X_train_normal, model_type="isolation_forest"):
    """
    TRUE anomaly detection setup: train only on normal traffic,
    so the model learns what 'normal' looks like from scratch.
    """
    if model_type == "isolation_forest":
        model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
        model.fit(X_train_normal)
        return model
    elif model_type == "lof":
        model = LocalOutlierFactor(n_neighbors=35, novelty=True, contamination=0.05, n_jobs=-1)
        model.fit(X_train_normal)
        return model


def evaluate_model(model, X_test, y_test):
    raw_scores = model.decision_function(X_test)
    anomaly_scores = -raw_scores
    preds = model.predict(X_test)
    preds = np.where(preds == -1, 1, 0)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, preds, average="binary", zero_division=0
    )
    cm = confusion_matrix(y_test, preds)
    return {
        "precision": round(precision, 4), "recall": round(recall, 4), "f1_score": round(f1, 4),
        "confusion_matrix": cm, "anomaly_scores": anomaly_scores, "preds": preds
    }


def per_category_detection_rate(test_df, preds):
    """Breakdown of detection rate by attack category (DoS/Probe/R2L/U2R)."""
    df = test_df.copy()
    df["category"] = df["label"].apply(get_attack_category)
    df["predicted_anomaly"] = preds

    results = {}
    for cat in ["DoS", "Probe", "R2L", "U2R"]:
        subset = df[df["category"] == cat]
        if len(subset) > 0:
            detection_rate = subset["predicted_anomaly"].mean()
            results[cat] = {"count": len(subset), "detection_rate": round(detection_rate, 4)}
    return results


def permutation_feature_importance(model, X_test, feature_cols, n_repeats=3, sample_size=3000):
    """
    Estimate feature importance by measuring how much the anomaly score
    distribution shifts when each feature is randomly shuffled.
    """
    rng = np.random.RandomState(42)
    idx = rng.choice(len(X_test), min(sample_size, len(X_test)), replace=False)
    X_sample = X_test[idx]

    baseline_scores = -model.decision_function(X_sample)
    importances = []

    for i in range(X_sample.shape[1]):
        diffs = []
        for _ in range(n_repeats):
            X_perm = X_sample.copy()
            rng.shuffle(X_perm[:, i])
            perm_scores = -model.decision_function(X_perm)
            diffs.append(np.mean(np.abs(perm_scores - baseline_scores)))
        importances.append(np.mean(diffs))

    imp_series = pd.Series(importances, index=feature_cols).sort_values(ascending=False)
    return imp_series


if __name__ == "__main__":
    print("Loading data...")
    train_df, test_df = load_data("../data/nsl-kdd/KDDTrain+.txt", "../data/nsl-kdd/KDDTest+.txt")
    X_train, X_test, y_train, y_test, scaler, encoders, feature_cols = preprocess(train_df, test_df)

    # TRUE anomaly detection: train only on normal rows
    X_train_normal = X_train[y_train == 0]
    print(f"Training on {X_train_normal.shape[0]} NORMAL-ONLY samples (true baseline, no attack data used)")

    print("\n=== Model 1: Isolation Forest (normal-only training) ===")
    if_model = train_on_normal_only(X_train_normal, "isolation_forest")
    if_results = evaluate_model(if_model, X_test, y_test)
    print(classification_report(y_test, if_results["preds"], target_names=["normal", "attack"], zero_division=0))

    print("\n=== Model 2: Local Outlier Factor (normal-only training) ===")
    lof_model = train_on_normal_only(X_train_normal, "lof")
    lof_results = evaluate_model(lof_model, X_test, y_test)
    print(classification_report(y_test, lof_results["preds"], target_names=["normal", "attack"], zero_division=0))

    # Pick best model
    best_name = "Isolation Forest" if if_results["f1_score"] >= lof_results["f1_score"] else "Local Outlier Factor"
    best_model = if_model if best_name == "Isolation Forest" else lof_model
    best_results = if_results if best_name == "Isolation Forest" else lof_results
    print(f"\n>>> Best model: {best_name} (F1={best_results['f1_score']})")

    # Per-attack-category breakdown
    print("\n=== Detection rate by attack category ===")
    cat_results = per_category_detection_rate(test_df, best_results["preds"])
    for cat, r in cat_results.items():
        print(f"  {cat}: {r['detection_rate']*100:.1f}% detected ({r['count']} samples)")

    # Feature importance
    print("\nComputing permutation feature importance (this takes a moment)...")
    importances = permutation_feature_importance(best_model, X_test, feature_cols)
    print("\nTop 10 most important features for anomaly scoring:")
    print(importances.head(10))

    # === Visualizations ===
    # 1. Confusion matrix heatmap
    plt.figure(figsize=(5, 4))
    sns.heatmap(best_results["confusion_matrix"], annot=True, fmt="d", cmap="Blues",
                xticklabels=["normal", "attack"], yticklabels=["normal", "attack"])
    plt.title(f"Confusion Matrix — {best_name}")
    plt.ylabel("True label")
    plt.xlabel("Predicted label")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    plt.close()

    # 2. Precision-Recall curve
    precisions, recalls, _ = precision_recall_curve(y_test, best_results["anomaly_scores"])
    pr_auc = auc(recalls, precisions)
    plt.figure(figsize=(5, 4))
    plt.plot(recalls, precisions, label=f"PR AUC = {pr_auc:.3f}")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title(f"Precision-Recall Curve — {best_name}")
    plt.legend()
    plt.tight_layout()
    plt.savefig("precision_recall_curve.png", dpi=150)
    plt.close()

    # 3. Per-category detection rate bar chart
    plt.figure(figsize=(6, 4))
    cats = list(cat_results.keys())
    rates = [cat_results[c]["detection_rate"] * 100 for c in cats]
    plt.bar(cats, rates, color=["#e74c3c", "#e67e22", "#f39c12", "#c0392b"])
    plt.ylabel("Detection Rate (%)")
    plt.title("Anomaly Detection Rate by Attack Category")
    plt.ylim(0, 100)
    for i, r in enumerate(rates):
        plt.text(i, r + 2, f"{r:.1f}%", ha="center")
    plt.tight_layout()
    plt.savefig("detection_rate_by_category.png", dpi=150)
    plt.close()

    # 4. Feature importance bar chart
    plt.figure(figsize=(7, 5))
    top_features = importances.head(10)
    plt.barh(top_features.index[::-1], top_features.values[::-1], color="#2980b9")
    plt.xlabel("Importance (mean anomaly score shift)")
    plt.title("Top 10 Features Driving Anomaly Detection")
    plt.tight_layout()
    plt.savefig("feature_importance.png", dpi=150)
    plt.close()

    print("\nSaved 4 visualizations: confusion_matrix.png, precision_recall_curve.png, "
          "detection_rate_by_category.png, feature_importance.png")

    # Save best model + metadata
    joblib.dump(best_model, "anomaly_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(encoders, "encoders.pkl")

    summary = {
        "best_model": best_name,
        "test_precision": best_results["precision"],
        "test_recall": best_results["recall"],
        "test_f1": best_results["f1_score"],
        "pr_auc": round(pr_auc, 4),
        "detection_by_category": cat_results,
        "top_features": importances.head(10).to_dict()
    }
    import json
    with open("model_summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print("\nSaved model_summary.json with full evaluation results")
