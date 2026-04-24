"""Train XGBoost model on ModSecurity dataset (modsec_xgb baseline)."""

from __future__ import annotations

import argparse
import json
import sys
import pickle
from pathlib import Path

import pandas as pd
import mlflow
import mlflow.sklearn
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, StratifiedShuffleSplit, cross_validate, train_test_split
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier

# Make src importable when running script directly
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.modsec_parser import load_dataset


def _build_pipeline(use_smote: bool = False, smote_k: int = 5) -> Pipeline:
    """Build preprocessing + XGBoost pipeline."""
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

    if use_smote:
        return ImbPipeline(
            steps=[
                ("preprocess", preprocessor),
                ("smote", SMOTE(random_state=42, k_neighbors=smote_k)),
                ("model", model),
            ]
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
    model_output: str = "models/trained_models/modsec_xgb_new.pkl",
    metrics_output: str = "models/trained_models/modsec_metrics_new.json",
    test_size: float = 0.2,
    random_state: int = 42,
    n_splits: int = 5,
    run_cv: bool = True,
    use_smote: bool = False,
    cv_method: str = "kfold",
    mlflow_experiment: str = "ojs-modsecurity-attack-detection",
    mlflow_run_name: str | None = None,
) -> dict:
    """Train XGBoost model."""
    print("[INFO] Loading dataset:", dataset_path)
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
    if "rule_count" not in df.columns:
        df["rule_count"] = 0
    if "has_suspicious_path" not in df.columns:
        df["has_suspicious_path"] = 0
    if "has_sqli_pattern" not in df.columns:
        df["has_sqli_pattern"] = 0
    if "has_xss_pattern" not in df.columns:
        df["has_xss_pattern"] = 0
    if "has_path_traversal" not in df.columns:
        df["has_path_traversal"] = 0
    if "has_command_injection" not in df.columns:
        df["has_command_injection"] = 0

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
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Determine SMOTE k_neighbors based on minority count
    smote_k = 5
    if use_smote:
        minority_count = y_train.value_counts().min()
        smote_k = max(1, min(5, minority_count - 1))
        print(f"[INFO] SMOTE k_neighbors set to {smote_k} based on minority class size {minority_count}.")

    # Build pipeline
    pipeline = _build_pipeline(use_smote=use_smote, smote_k=smote_k)

    cv_results = None
    if run_cv:
        print(f"[INFO] Running {n_splits}-fold cross-validation ({cv_method})...")
        if cv_method == "shuffle":
            cv = StratifiedShuffleSplit(
                n_splits=n_splits,
                test_size=test_size,
                random_state=random_state,
            )
        else:
            cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

        cv_results = cross_validate(
            pipeline,
            X_train,
            y_train,
            cv=cv,
            scoring=["accuracy", "f1", "precision", "recall", "roc_auc"],
            return_train_score=False,
        )

        for metric in ["accuracy", "f1", "precision", "recall", "roc_auc"]:
            scores = cv_results[f"test_{metric}"]
            print(f"  {metric:12} - mean: {scores.mean():.4f}, std: {scores.std():.4f}")

    # Train final model
    print("[INFO] Training final model...")
    pipeline.fit(X_train, y_train)

    # Evaluate on test set
    y_test_pred = pipeline.predict(X_test)
    y_test_prob = pipeline.predict_proba(X_test)[:, 1]

    test_metrics = _compute_metrics(y_test, y_test_pred, y_test_prob)

    print("\n" + "=" * 60)
    print("TEST METRICS")
    print("=" * 60)
    for metric, value in test_metrics.items():
        print(f"  {metric:12}: {value:.4f}")

    # Save model
    model_path = Path(model_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, 'wb') as f:
        pickle.dump(pipeline, f)
    print(f"\n[INFO] Model saved to {model_path}")

    # Save metrics
    summary = {
        "test_metrics": test_metrics,
        "test_dataset_size": int(len(X_test)),
        "train_dataset_size": int(len(X_train)),
        "confusion_matrix": confusion_matrix(y_test, y_test_pred).tolist(),
    }

    if cv_results is not None:
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

    mlflow.set_tracking_uri("mlruns")
    print(f"[INFO] MLflow tracking URI: {mlflow.get_tracking_uri()}")
    mlflow.set_experiment(mlflow_experiment)
    with mlflow.start_run(run_name=mlflow_run_name):
        mlflow.log_params(
            {
                "dataset_path": dataset_path,
                "test_size": test_size,
                "random_state": random_state,
                "use_smote": use_smote,
                "cv_method": cv_method,
                "n_splits": n_splits if run_cv else 0,
                "n_estimators": 300,
                "max_depth": 6,
                "learning_rate": 0.05,
                "subsample": 0.9,
                "colsample_bytree": 0.9,
                "objective": "binary:logistic",
                "eval_metric": "logloss",
            }
        )
        for metric_name, metric_value in test_metrics.items():
            mlflow.log_metric(f"test_{metric_name}", metric_value)
        if cv_results is not None:
            for metric_name in ["accuracy", "f1", "precision", "recall", "roc_auc"]:
                mlflow.log_metric(f"cv_{metric_name}_mean", summary["cv_metrics"][f"{metric_name}_mean"])
                mlflow.log_metric(f"cv_{metric_name}_std", summary["cv_metrics"][f"{metric_name}_std"])
        class_report = classification_report(y_test, y_test_pred)
        mlflow.log_text(class_report, "classification_report.txt")
        mlflow.sklearn.log_model(pipeline, "xgboost_pipeline")

    with open(metrics_output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[INFO] Metrics saved to {metrics_output}")

    # Show confusion matrix
    cm = confusion_matrix(y_test, y_test_pred)
    print("\nConfusion Matrix:")
    print(f"  TN: {cm[0, 0]}, FP: {cm[0, 1]}")
    print(f"  FN: {cm[1, 0]}, TP: {cm[1, 1]}")

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train XGBoost model on ModSecurity dataset (modsec baseline)."
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to dataset CSV (e.g., data/dataset/modsec_raw_processed_updated.csv)",
    )
    parser.add_argument(
        "--model-output",
        default="models/trained_models/modsec_xgb.pkl",
        help="Output path for trained model (pickle).",
    )
    parser.add_argument(
        "--metrics-output",
        default="models/trained_models/modsec_metrics.json",
        help="Output path for metrics JSON.",
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Test set fraction.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument(
        "--cv-splits", type=int, default=5, help="Number of CV folds or iterations."
    )
    parser.add_argument(
        "--cv-method",
        choices=["kfold", "shuffle"],
        default="kfold",
        help="Cross-validation method: kfold or stratified shuffle split.",
    )
    parser.add_argument(
        "--use-smote",
        action="store_true",
        help="Apply SMOTE oversampling to the training set before training.",
    )
    parser.add_argument(
        "--mlflow-experiment",
        default="ojs-modsecurity-attack-detection",
        help="MLflow experiment name.",
    )
    parser.add_argument(
        "--mlflow-run-name",
        default=None,
        help="MLflow run name.",
    )
    parser.add_argument(
        "--no-cv", action="store_true", help="Skip cross-validation."
    )

    args = parser.parse_args()

    train(
        dataset_path=args.dataset,
        model_output=args.model_output,
        metrics_output=args.metrics_output,
        test_size=args.test_size,
        random_state=args.random_state,
        n_splits=args.cv_splits,
        run_cv=not args.no_cv,
        use_smote=args.use_smote,
        cv_method=args.cv_method,
        mlflow_experiment=args.mlflow_experiment,
        mlflow_run_name=args.mlflow_run_name,
    )

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
