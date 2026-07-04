"""
Data Preprocessing for NSL-KDD Dataset
Module 1: Behavioural Anomaly Detection Engine

Loads NSL-KDD network traffic data, encodes categorical features,
scales numerical features, and prepares train/test splits for
unsupervised anomaly detection.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Standard NSL-KDD 41 feature columns + label + difficulty score
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def load_data(train_path, test_path):
    """Load NSL-KDD train and test sets with proper column names."""
    train_df = pd.read_csv(train_path, names=COLUMN_NAMES)
    test_df = pd.read_csv(test_path, names=COLUMN_NAMES)
    return train_df, test_df


def binarize_labels(df):
    """Convert multi-class attack labels into binary: normal (0) vs attack (1)."""
    df = df.copy()
    df["binary_label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
    return df


def preprocess(train_df, test_df):
    """
    Encode categorical columns and scale numerical features.
    Returns processed train/test feature matrices + binary labels.
    """
    train_df = binarize_labels(train_df)
    test_df = binarize_labels(test_df)

    # Drop label/difficulty columns from features
    feature_cols = [c for c in COLUMN_NAMES if c not in ("label", "difficulty")]

    X_train = train_df[feature_cols].copy()
    X_test = test_df[feature_cols].copy()

    # Encode categorical columns (fit on combined train+test to avoid unseen categories)
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        combined = pd.concat([X_train[col], X_test[col]], axis=0)
        le.fit(combined)
        X_train[col] = le.transform(X_train[col])
        X_test[col] = le.transform(X_test[col])
        encoders[col] = le

    # Scale numerical features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    y_train = train_df["binary_label"].values
    y_test = test_df["binary_label"].values

    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, encoders, feature_cols


if __name__ == "__main__":
    train_df, test_df = load_data(
        "../data/nsl-kdd/KDDTrain+.txt",
        "../data/nsl-kdd/KDDTest+.txt"
    )
    print("Train shape:", train_df.shape)
    print("Test shape:", test_df.shape)
    print("\nLabel distribution (train):")
    print(train_df["label"].value_counts().head(10))

    X_train, X_test, y_train, y_test, scaler, encoders, feature_cols = preprocess(train_df, test_df)
    print("\nProcessed X_train shape:", X_train.shape)
    print("Binary label distribution (train): normal=%d, attack=%d" % (
        (y_train == 0).sum(), (y_train == 1).sum()
    ))
