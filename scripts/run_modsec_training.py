"""Train XGBoost model on ModSecurity dataset (modsec_xgb baseline)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import pickle
from pathlib import Path

import optuna
import pandas as pd
import mlflow
import mlflow.sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    GridSearchCV,
    StratifiedKFold,
    StratifiedShuffleSplit,
    cross_validate,
    train_test_split,
)
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
from src.utils.config import get_config


def _build_model(random_state: int = 42, device: str = "cpu", **overrides) -> XGBClassifier:
    base_params = {
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.9,
        "colsample_bytree": 0.9,
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "random_state": random_state,
        "n_jobs": 1,
        "device": device,
    }
    if device == "cuda":
        base_params["tree_method"] = "hist"
    base_params.update(overrides)
    return XGBClassifier(**base_params)


def _build_pipeline(model: XGBClassifier | None = None, use_smote: bool = False, smote_k: int = 5) -> Pipeline:
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
        "has_path_traversal",
        "has_command_injection",
        "has_cve_2022_24181",
        "missing_csrf_token",
        "has_suspicious_referer",
        "has_cve_2024_xss_privesc",
        "has_privesc_attempt",
        "has_cve_2021_32626",
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

    if model is None:
        model = _build_model()

    if use_smote:
        return ImbPipeline(
            steps=[
                ("preprocess", preprocessor),
                ("smote", SMOTE(random_state=42, k_neighbors=smote_k)),
                ("model", model),
            ]
        )

    return Pipeline(steps=[("preprocess", preprocessor), ("model", model)])


def _suggest_xgb_params(trial: optuna.Trial, config=None) -> dict[str, object]:
    # Use aggressive search space from config if available
    if config and "hyperparameter_search_space" in config.config:
        space = config.config["hyperparameter_search_space"]
        return {
            "n_estimators": trial.suggest_int(
                "n_estimators",
                space.get("n_estimators", {}).get("min", 100),
                space.get("n_estimators", {}).get("max", 1000),
                step=space.get("n_estimators", {}).get("step", 50),
            ),
            "max_depth": trial.suggest_int(
                "max_depth",
                space.get("max_depth", {}).get("min", 3),
                space.get("max_depth", {}).get("max", 12),
            ),
            "learning_rate": trial.suggest_float(
                "learning_rate",
                space.get("learning_rate", {}).get("min", 0.001),
                space.get("learning_rate", {}).get("max", 0.3),
                log=space.get("learning_rate", {}).get("log", True),
            ),
            "subsample": trial.suggest_float(
                "subsample",
                space.get("subsample", {}).get("min", 0.5),
                space.get("subsample", {}).get("max", 1.0),
            ),
            "colsample_bytree": trial.suggest_float(
                "colsample_bytree",
                space.get("colsample_bytree", {}).get("min", 0.5),
                space.get("colsample_bytree", {}).get("max", 1.0),
            ),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "gamma": trial.suggest_float(
                "gamma",
                space.get("gamma", {}).get("min", 0.0),
                space.get("gamma", {}).get("max", 10.0),
            ),
            "reg_alpha": trial.suggest_float(
                "reg_alpha",
                space.get("reg_alpha", {}).get("min", 1e-8),
                space.get("reg_alpha", {}).get("max", 100.0),
                log=space.get("reg_alpha", {}).get("log", True),
            ),
            "reg_lambda": trial.suggest_float(
                "reg_lambda",
                space.get("reg_lambda", {}).get("min", 1e-3),
                space.get("reg_lambda", {}).get("max", 100.0),
                log=space.get("reg_lambda", {}).get("log", True),
            ),
        }
    
    # Fallback to baseline search space
    return {
        "n_estimators": trial.suggest_int("n_estimators", 200, 700, step=50),
        "max_depth": trial.suggest_int("max_depth", 3, 8),
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "subsample": trial.suggest_float("subsample", 0.6, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
        "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
        "gamma": trial.suggest_float("gamma", 0.0, 5.0),
        "reg_alpha": trial.suggest_float("reg_alpha", 1e-8, 10.0, log=True),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 10.0, log=True),
    }


def _run_optuna_search(
    X_train,
    y_train,
    cv,
    random_state: int,
    n_trials: int,
    device: str = "cpu",
    use_smote: bool = False,
    smote_k: int = 5,
    config=None,
):
    def objective(trial: optuna.Trial) -> float:
        params = _suggest_xgb_params(trial, config=config)
        model = _build_model(random_state=random_state, device=device, **params)
        pipeline = _build_pipeline(model=model, use_smote=use_smote, smote_k=smote_k)
        scores = cross_validate(
            pipeline,
            X_train,
            y_train,
            cv=cv,
            scoring=["roc_auc"],
            n_jobs=1,
            return_train_score=False,
        )
        return float(scores["test_roc_auc"].mean())

    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=random_state))
    study.optimize(objective, n_trials=n_trials, show_progress_bar=False)

    best_model = _build_model(random_state=random_state, device=device, **study.best_params)
    return best_model, study


def _build_automl_search(use_smote: bool = False, smote_k: int = 5, cv=None) -> GridSearchCV:
    """Create an AutoML search over candidate models and hyperparameters."""
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
        "missing_csrf_token",
        "has_suspicious_referer",
        "has_cve_2024_xss_privesc",
        "has_privesc_attempt",
        "has_cve_2021_32626",
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

    base_pipeline: Pipeline | ImbPipeline
    if use_smote:
        base_pipeline = ImbPipeline(
            steps=[
                ("preprocess", preprocessor),
                ("smote", SMOTE(random_state=42, k_neighbors=smote_k)),
                ("model", LogisticRegression()),
            ]
        )
    else:
        base_pipeline = Pipeline(
            steps=[
                ("preprocess", preprocessor),
                ("model", LogisticRegression()),
            ]
        )

    param_grid = [
        {
            "model": [LogisticRegression(max_iter=1000, solver="lbfgs", random_state=42)],
            "model__C": [0.1, 1.0, 10.0],
        },
        {
            "model": [RandomForestClassifier(random_state=42, n_jobs=1)],
            "model__n_estimators": [100, 200],
            "model__max_depth": [None, 8, 16],
            "model__min_samples_leaf": [1, 3],
        },
        {
            "model": [
                XGBClassifier(
                    random_state=42,
                    use_label_encoder=False,
                    eval_metric="logloss",
                    n_jobs=1,
                )
            ],
            "model__n_estimators": [100, 200],
            "model__max_depth": [4, 6],
            "model__learning_rate": [0.05, 0.1],
        },
    ]

    return GridSearchCV(
        estimator=base_pipeline,
        param_grid=param_grid,
        scoring={
            "accuracy": "accuracy",
            "f1": "f1",
            "precision": "precision",
            "recall": "recall",
            "roc_auc": "roc_auc",
        },
        refit="roc_auc",
        cv=cv,
        n_jobs=-1,
        verbose=1,
        return_train_score=False,
    )


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
    use_automl: bool = False,
    use_optuna: bool = False,
    optuna_trials: int = 25,
    cv_method: str = "kfold",
    mlflow_experiment: str = "ojs-modsecurity-attack-detection",
    mlflow_run_name: str | None = None,
    threshold: float = 0.5,
    config=None,
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

    # Build or search for pipeline
    cv = None
    if cv_method == "shuffle":
        cv = StratifiedShuffleSplit(
            n_splits=n_splits,
            test_size=test_size,
            random_state=random_state,
        )
    else:
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    pipeline = None
    automl_search = None
    optuna_search = None
    optuna_best_params = None
    optuna_best_value = None
    training_device = "cuda"
    used_fallback_device = False
    cv_results = None

    if use_optuna:
        for candidate_device in ["cuda", "cpu"]:
            try:
                training_device = candidate_device
                print(f"[INFO] Running Optuna search with {optuna_trials} trials on {candidate_device}...")
                optuna_search, study = _run_optuna_search(
                    X_train=X_train,
                    y_train=y_train,
                    cv=cv,
                    random_state=random_state,
                    n_trials=optuna_trials,
                    device=candidate_device,
                    use_smote=use_smote,
                    smote_k=smote_k,
                    config=config,
                )
                optuna_best_params = study.best_params
                optuna_best_value = float(study.best_value)
                pipeline = _build_pipeline(model=optuna_search, use_smote=use_smote, smote_k=smote_k)
                print(f"[INFO] Optuna best ROC-AUC: {optuna_best_value:.4f}")
                print(f"[INFO] Optuna best params: {optuna_best_params}")
                if run_cv:
                    print(f"[INFO] Running {n_splits}-fold cross-validation on Optuna best model ({cv_method})...")
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
                break
            except Exception as exc:
                if candidate_device == "cuda":
                    used_fallback_device = True
                    print(f"[WARN] CUDA training failed, falling back to CPU. Reason: {exc}")
                    continue
                raise

        if pipeline is None:
            raise RuntimeError("Gagal membuat pipeline training untuk Optuna.")

        for candidate_device in [training_device, "cpu"]:
            try:
                if candidate_device != training_device:
                    used_fallback_device = True
                    training_device = candidate_device
                    print(f"[WARN] Refitting best Optuna model on CPU after GPU failure.")
                    pipeline = _build_pipeline(
                        model=_build_model(random_state=random_state, device=candidate_device, **(optuna_best_params or {})),
                        use_smote=use_smote,
                        smote_k=smote_k,
                    )

                print(f"[INFO] Training final Optuna model on {candidate_device}...")
                pipeline.fit(X_train, y_train)
                break
            except Exception as exc:
                if candidate_device == "cuda":
                    used_fallback_device = True
                    print(f"[WARN] Final CUDA fit failed, falling back to CPU. Reason: {exc}")
                    continue
                raise
    elif use_automl:
        print("[INFO] Running AutoML search across candidate models...")
        automl_search = _build_automl_search(use_smote=use_smote, smote_k=smote_k, cv=cv)
        automl_search.fit(X_train, y_train)
        pipeline = automl_search.best_estimator_

        print(f"[INFO] AutoML selected best model: {type(pipeline.named_steps['model']).__name__}")
        print(f"[INFO] AutoML best params: {automl_search.best_params_}")
        if run_cv:
            print(f"[INFO] Running {n_splits}-fold cross-validation on AutoML best model ({cv_method})...")
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
    else:
        for candidate_device in ["cuda", "cpu"]:
            try:
                training_device = candidate_device
                pipeline = _build_pipeline(
                    model=_build_model(random_state=random_state, device=candidate_device),
                    use_smote=use_smote,
                    smote_k=smote_k,
                )
                if run_cv:
                    print(f"[INFO] Running {n_splits}-fold cross-validation ({cv_method}) on {candidate_device}...")
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

                print(f"[INFO] Training final model on {candidate_device}...")
                pipeline.fit(X_train, y_train)
                break
            except Exception as exc:
                if candidate_device == "cuda":
                    used_fallback_device = True
                    print(f"[WARN] CUDA training failed, falling back to CPU. Reason: {exc}")
                    continue
                raise
        if pipeline is None:
            raise RuntimeError("Gagal membuat pipeline training.")

    # Evaluate on test set
    y_test_prob = pipeline.predict_proba(X_test)[:, 1]
    
    # Apply custom threshold (default 0.5 = sklearn default)
    if threshold != 0.5:
        print(f"[INFO] Using custom threshold: {threshold}")
        y_test_pred = (y_test_prob >= threshold).astype(int)
    else:
        y_test_pred = pipeline.predict(X_test)

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
        "use_automl": use_automl,
        "use_optuna": use_optuna,
        "training_device": training_device,
        "used_fallback_device": used_fallback_device,
        "threshold": float(threshold),
    }
    if use_automl and automl_search is not None:
        summary["automl_best_params"] = automl_search.best_params_
        summary["automl_best_model"] = type(pipeline.named_steps["model"]).__name__
    if use_optuna and optuna_search is not None:
        summary["optuna_best_value"] = optuna_best_value
        summary["optuna_best_params"] = optuna_best_params
        summary["optuna_best_model"] = type(pipeline.named_steps["model"]).__name__

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
        params = {
            "dataset_path": dataset_path,
            "test_size": test_size,
            "random_state": random_state,
            "use_smote": use_smote,
            "use_automl": use_automl,
            "use_optuna": use_optuna,
            "training_device": training_device,
            "used_fallback_device": used_fallback_device,
            "cv_method": cv_method,
            "n_splits": n_splits if run_cv else 0,
            "threshold": threshold,
        }
        if use_automl and automl_search is not None:
            params["automl_best_model"] = type(pipeline.named_steps["model"]).__name__
            params["automl_best_params"] = json.dumps(automl_search.best_params_, default=str)
        elif use_optuna and optuna_search is not None:
            params["optuna_best_model"] = type(pipeline.named_steps["model"]).__name__
            params["optuna_best_value"] = optuna_best_value
            params["optuna_best_params"] = json.dumps(optuna_best_params, default=str)
        else:
            params.update(
                {
                    "n_estimators": 300,
                    "max_depth": 6,
                    "learning_rate": 0.05,
                    "subsample": 0.9,
                    "colsample_bytree": 0.9,
                    "objective": "binary:logistic",
                    "eval_metric": "logloss",
                }
            )
        mlflow.log_params(params)
        for metric_name, metric_value in test_metrics.items():
            mlflow.log_metric(f"test_{metric_name}", metric_value)
        if cv_results is not None:
            for metric_name in ["accuracy", "f1", "precision", "recall", "roc_auc"]:
                mlflow.log_metric(f"cv_{metric_name}_mean", summary["cv_metrics"][f"{metric_name}_mean"])
                mlflow.log_metric(f"cv_{metric_name}_std", summary["cv_metrics"][f"{metric_name}_std"])
        class_report = classification_report(y_test, y_test_pred)
        mlflow.log_text(class_report, "classification_report.txt")
        model_name = type(pipeline.named_steps["model"]).__name__ if "model" in pipeline.named_steps else "pipeline"
        mlflow.sklearn.log_model(pipeline, f"{model_name}_pipeline")

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
    # Load config (will use defaults if not customized)
    config = get_config()
    default_threshold = config.get_threshold()
    default_optuna_trials = config.config.get("training", {}).get("optuna_trials", 25)
    
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
        "--auto-ml",
        action="store_true",
        help="Run AutoML search to select the best model and hyperparameters.",
    )
    parser.add_argument(
        "--use-optuna",
        action="store_true",
        help="Run Optuna tuning for the XGBoost model on ModSecurity features.",
    )
    parser.add_argument(
        "--optuna-trials",
        type=int,
        default=default_optuna_trials,
        help=f"Number of Optuna trials to run. Default: {default_optuna_trials} (from config).",
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
    parser.add_argument(
        "--threshold",
        type=float,
        default=default_threshold,
        help=f"Decision threshold for predictions (0.0-1.0). Default: {default_threshold} (from config). "
             f"Override with env var: MODEL_INFERENCE_THRESHOLD",
    )

    args = parser.parse_args()
    
    # Check if threshold override from environment
    env_threshold = os.getenv("MODEL_INFERENCE_THRESHOLD")
    if env_threshold:
        args.threshold = float(env_threshold)
        print(f"[INFO] Threshold overridden by MODEL_INFERENCE_THRESHOLD={args.threshold}")
    else:
        print(f"[INFO] Using threshold from config: {args.threshold}")

    train(
        dataset_path=args.dataset,
        model_output=args.model_output,
        metrics_output=args.metrics_output,
        test_size=args.test_size,
        random_state=args.random_state,
        n_splits=args.cv_splits,
        run_cv=not args.no_cv,
        use_smote=args.use_smote,
        use_automl=args.auto_ml,
        use_optuna=args.use_optuna,
        optuna_trials=args.optuna_trials,
        cv_method=args.cv_method,
        mlflow_experiment=args.mlflow_experiment,
        mlflow_run_name=args.mlflow_run_name,
        threshold=args.threshold,
        config=config,
    )

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
