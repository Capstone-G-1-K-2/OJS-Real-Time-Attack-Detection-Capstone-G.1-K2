from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import mlflow
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier

from src.preprocessing.modsec_parser import load_dataset


def _build_pipeline() -> Pipeline:
    numeric_features = [
        "status",
        "bytes_sent",
        "request_time",
        "rule_count",
        "severity_score",
        "user_agent_len",
        "uri_len",
        "has_sqli_pattern",
        "has_xss_pattern",
        "has_suspicious_path",
    ]
    categorical_features = ["method"]
    text_feature = "uri"

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", "passthrough", numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("txt", TfidfVectorizer(max_features=300), text_feature),
        ],
        remainder="drop",
    )

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
    )

    return Pipeline(steps=[("preprocess", preprocessor), ("model", model)])


def train(dataset_path: str, model_output: str, test_size: float, random_state: int) -> dict:
    df = load_dataset(dataset_path)

    if "label" not in df.columns:
        raise ValueError("Dataset harus punya kolom 'label' (0 = normal, 1 = attack).")

    required_columns = {
        "method",
        "uri",
        "status",
        "bytes_sent",
        "request_time",
        "rule_count",
        "severity_score",
        "user_agent_len",
        "uri_len",
        "has_sqli_pattern",
        "has_xss_pattern",
        "has_suspicious_path",
        "label",
    }

    missing = required_columns.difference(df.columns)
    if missing:
        raise ValueError(f"Kolom dataset kurang: {sorted(missing)}")

    X = df.drop(columns=["label"])
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    pipeline = _build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
    }

    mlflow.set_experiment("ojs-modsecurity-attack-detection")
    with mlflow.start_run():
        mlflow.log_params(
            {
                "dataset_path": dataset_path,
                "test_size": test_size,
                "random_state": random_state,
                "model": "xgboost",
            }
        )
        mlflow.log_metrics(metrics)
        mlflow.log_text(classification_report(y_test, y_pred), "classification_report.txt")

        model_path = Path(model_output)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, model_path)
        mlflow.log_artifact(str(model_path))

    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train OJS attack detection model from ModSecurity dataset.")
    parser.add_argument("--dataset", required=True, help="Path ke dataset CSV/JSONL.")
    parser.add_argument(
        "--model-output",
        default="models/trained_models/modsec_xgb.joblib",
        help="Output path model joblib.",
    )
    parser.add_argument("--metrics-output", default="models/trained_models/modsec_metrics.json")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)

    args = parser.parse_args()
    metrics = train(args.dataset, args.model_output, args.test_size, args.random_state)

    metrics_path = Path(args.metrics_output)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("Training selesai.")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
