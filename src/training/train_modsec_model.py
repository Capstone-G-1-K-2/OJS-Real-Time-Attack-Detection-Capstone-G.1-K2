from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Setup path so imports work when running directly
PROJECT_ROOT = Path(__file__).resolve().parents[2]  # Go up 2 levels from src/training/
sys.path.insert(0, str(PROJECT_ROOT))

import pickle
import mlflow
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
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
        "has_path_traversal",
        "has_command_injection",
        "has_cve_2022_24181",
        "has_cve_2023_47271_upload",
        "has_cve_2023_47271_rce",
        "missing_csrf_token",
        "has_suspicious_referer",
        "has_cve_2024_xss_privesc",
        "has_privesc_attempt",
        "has_cve_2021_32626",
        "has_cve_2023_47271_upload",
        "has_cve_2023_47271_rce",
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


def _compute_metrics(y_true, y_pred, y_prob) -> dict:
    """Compute comprehensive metrics."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
    }


def train(
    dataset_path: str,
    model_output: str,
    test_size: float,
    random_state: int,
    n_splits: int = 5,
    run_cv: bool = True,
) -> dict:
    """Train XGBoost model with cross-validation.

    Args:
        dataset_path: Path ke dataset CSV/JSONL.
        model_output: Output path untuk model pickle.
        test_size: Proporsi test set.
        random_state: Random seed.
        n_splits: Jumlah folds untuk cross-validation.
        run_cv: Jalankan cross-validation.

    Returns:
        Dictionary berisi test metrics dan CV scores.
    """
    print(f"[INFO] Loading dataset: {dataset_path}")
    df = load_dataset(dataset_path)

    if "label" not in df.columns:
        raise ValueError("Dataset harus punya kolom 'label' (0 = normal, 1 = attack).")

    # Drop old pattern columns if pattern versions exist (avoid duplicates)
    if "has_sqli_pattern" in df.columns and "has_sqli" in df.columns:
        df = df.drop(columns=["has_sqli"])
    if "has_xss_pattern" in df.columns and "has_xss" in df.columns:
        df = df.drop(columns=["has_xss"])
    
    # Rename columns from CSV format to training format if needed
    column_mapping = {
        "has_sqli": "has_sqli_pattern",
        "has_xss": "has_xss_pattern",
    }
    df = df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns})
    
    # Add missing columns with defaults
    default_columns = [
        "rule_count", "has_suspicious_path", "has_sqli_pattern", "has_xss_pattern",
        "has_path_traversal", "has_command_injection", "has_cve_2022_24181",
        "has_cve_2023_47271_upload", "has_cve_2023_47271_rce",
        "missing_csrf_token", "has_suspicious_referer", "has_cve_2024_xss_privesc",
        "has_privesc_attempt", "has_cve_2021_32626", "has_cve_2023_47271_upload", "has_cve_2023_47271_rce"
    ]
    for col in default_columns:
        if col not in df.columns:
            df[col] = 0

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
        "has_path_traversal",
        "has_command_injection",
        "has_cve_2022_24181",
        "has_cve_2023_47271_upload",
        "has_cve_2023_47271_rce",
        "missing_csrf_token",
        "has_suspicious_referer",
        "has_cve_2024_xss_privesc",
        "has_privesc_attempt",
        "has_cve_2021_32626",
        "has_cve_2023_47271_upload",
        "has_cve_2023_47271_rce",
        "label",
    }

    missing = required_columns.difference(df.columns)
    if missing:
        raise ValueError(f"Kolom dataset kurang: {sorted(missing)}")

    X = df.drop(columns=["label"])
    y = df["label"].astype(int)

    print(f"[INFO] Dataset shape: {X.shape}, Class distribution: {y.value_counts().to_dict()}")

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    # Compute custom sample weights for training
    import numpy as np
    sample_weights = np.ones(len(y_train))
    cve_mask = ((X_train["has_cve_2023_47271_upload"] == 1) | (X_train["has_cve_2023_47271_rce"] == 1)) & (y_train == 1)
    sample_weights[cve_mask] = 10.0

    fit_params = {"model__sample_weight": sample_weights}

    pipeline = _build_pipeline()

    # Cross-validation on training set
    cv_results = None
    if run_cv:
        print(f"[INFO] Running {n_splits}-fold cross-validation...")
        skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
        cv_results = cross_validate(
            pipeline,
            X_train,
            y_train,
            cv=skf,
            scoring=["accuracy", "f1", "precision", "recall", "roc_auc"],
            return_train_score=True,
            fit_params=fit_params,
        )
        print("[INFO] Cross-validation complete.")

    # Train final model on full training set
    print("[INFO] Training final model...")
    pipeline.fit(X_train, y_train, **fit_params)

    # Evaluate on test set
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    test_metrics = _compute_metrics(y_test, y_pred, y_prob)

    # Summary metrics
    summary = {
        "test_metrics": test_metrics,
        "test_dataset_size": int(len(X_test)),
        "train_dataset_size": int(len(X_train)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    if cv_results:
        cv_summary = {
            "n_splits": n_splits,
            "accuracy_mean": float(cv_results["test_accuracy"].mean()),
            "accuracy_std": float(cv_results["test_accuracy"].std()),
            "f1_mean": float(cv_results["test_f1"].mean()),
            "f1_std": float(cv_results["test_f1"].std()),
            "precision_mean": float(cv_results["test_precision"].mean()),
            "precision_std": float(cv_results["test_precision"].std()),
            "recall_mean": float(cv_results["test_recall"].mean()),
            "recall_std": float(cv_results["test_recall"].std()),
            "roc_auc_mean": float(cv_results["test_roc_auc"].mean()),
            "roc_auc_std": float(cv_results["test_roc_auc"].std()),
        }
        summary["cv_metrics"] = cv_summary

    # Save model
    model_path = Path(model_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, 'wb') as f:
        pickle.dump(pipeline, f)
    print(f"[INFO] Model saved to {model_path}")

    # MLflow logging
    mlflow.set_experiment("ojs-modsecurity-attack-detection")
    with mlflow.start_run():
        # Log parameters
        mlflow.log_params(
            {
                "dataset_path": dataset_path,
                "test_size": test_size,
                "random_state": random_state,
                "model": "xgboost",
                "n_splits": n_splits if run_cv else 0,
            }
        )

        # Log test metrics
        for metric_name, metric_value in test_metrics.items():
            mlflow.log_metric(f"test_{metric_name}", metric_value)

        # Log CV metrics
        if cv_results:
            for metric_name, values in cv_results.items():
                if metric_name.startswith("test_"):
                    clean_name = metric_name.replace("test_", "cv_")
                    mlflow.log_metric(f"{clean_name}_mean", float(values.mean()))
                    mlflow.log_metric(f"{clean_name}_std", float(values.std()))

        # Log classification report
        class_report = classification_report(y_test, y_pred)
        mlflow.log_text(class_report, "classification_report.txt")

        # Log model artifact
        mlflow.log_artifact(str(model_path))

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Train OJS attack detection model from ModSecurity dataset.")
    parser.add_argument("--dataset", required=True, help="Path ke dataset CSV/JSONL.")
    parser.add_argument(
        "--model-output",
        default="models/trained_models/modsec_xgb.pkl",
        help="Output path model pickle.",
    )
    parser.add_argument("--metrics-output", default="models/trained_models/modsec_metrics.json")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--cv-splits", type=int, default=5, help="Jumlah folds untuk cross-validation.")
    parser.add_argument("--no-cv", action="store_true", help="Skip cross-validation.")

    args = parser.parse_args()
    
    summary = train(
        args.dataset,
        args.model_output,
        args.test_size,
        args.random_state,
        n_splits=args.cv_splits,
        run_cv=not args.no_cv,
    )

    metrics_path = Path(args.metrics_output)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print("\nTest Metrics:")
    for metric_name, value in summary["test_metrics"].items():
        print(f"  {metric_name}: {value:.4f}")
    
    if "cv_metrics" in summary:
        print("\nCross-Validation Metrics (mean ± std):")
        for metric_name, value in summary["cv_metrics"].items():
            if "_mean" in metric_name:
                base_name = metric_name.replace("_mean", "")
                std_key = f"{base_name}_std"
                if std_key in summary["cv_metrics"]:
                    print(f"  {base_name}: {value:.4f} ± {summary['cv_metrics'][std_key]:.4f}")
    
    print(f"\nMetrics saved to: {metrics_path}")
    print(f"Model saved to: {args.model_output}")


if __name__ == "__main__":
    main()
