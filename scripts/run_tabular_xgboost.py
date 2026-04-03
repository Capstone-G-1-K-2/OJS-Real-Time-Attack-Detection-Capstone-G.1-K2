from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier

# Make src importable when running script directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.modsec_parser import load_dataset
from src.preprocessing.tabular_features import build_tabular_features


def evaluate(y_true: pd.Series, y_pred: pd.Series, y_prob: pd.Series) -> dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run tabular feature engineering + XGBoost baseline.")
    parser.add_argument("--dataset", required=True, help="Path dataset (CSV atau folder/file raw log).")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--max-samples", type=int, default=0)
    parser.add_argument("--output-dir", default="models/model_registry/tabular_xgboost")
    parser.add_argument("--cv-splits", type=int, default=5, help="Jumlah folds untuk cross-validation.")
    parser.add_argument("--no-cv", action="store_true", help="Skip cross-validation.")
    
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset tidak ditemukan: {dataset_path}")

    print(f"[INFO] Loading dataset: {dataset_path}", flush=True)
    df = load_dataset(dataset_path) if dataset_path.suffix.lower() != ".csv" else pd.read_csv(dataset_path)
    if df.empty:
        raise ValueError("Dataset kosong.")

    if args.max_samples and args.max_samples > 0 and len(df) > args.max_samples:
        df = df.sample(n=args.max_samples, random_state=args.random_state)
        print(f"[INFO] Sampling applied: {len(df)} rows", flush=True)

    if args.label_col not in df.columns:
        raise ValueError(f"Kolom label tidak ditemukan: {args.label_col}")

    print(f"[INFO] Building tabular features...", flush=True)
    y = pd.to_numeric(df[args.label_col], errors="coerce").fillna(0).astype(int)
    X = build_tabular_features(df)

    if y.nunique() < 2:
        raise ValueError("Label harus punya minimal dua kelas (0 dan 1).")

    print(f"[INFO] Dataset shape: {X.shape}, Class distribution: {y.value_counts().to_dict()}", flush=True)

    # Separate features for preprocessing
    cat_cols = ["method"] if "method" in X.columns else []
    text_col = "uri" if "uri" in X.columns else None
    num_cols = [c for c in X.columns if c not in cat_cols and c != text_col]

    # Build transformers (same as training pipeline)
    transformers = [
        ("num", "passthrough", num_cols),
        ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
    ]
    
    # Add TF-IDF for text if uri column exists
    if text_col:
        transformers.append(("txt", TfidfVectorizer(max_features=300), text_col))

    preprocessor = ColumnTransformer(
        transformers=transformers,
        remainder="drop",
    )

    model = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=args.random_state,
    )

    pipeline = Pipeline([
        ("preprocess", preprocessor),
        ("model", model),
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    print("[INFO] Training tabular XGBoost...", flush=True)
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]
    metrics = evaluate(y_test, y_pred, y_prob)

    # Cross-validation
    cv_results = None
    if not args.no_cv:
        print(f"[INFO] Running {args.cv_splits}-fold cross-validation...", flush=True)
        skf = StratifiedKFold(n_splits=args.cv_splits, shuffle=True, random_state=args.random_state)
        cv_results = cross_validate(
            pipeline,
            X_train,
            y_train,
            cv=skf,
            scoring=["accuracy", "f1", "precision", "recall", "roc_auc"],
            return_train_score=True,
        )
        print("[INFO] Cross-validation complete.", flush=True)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "tabular_xgboost.joblib"
    result_path = output_dir / "result.json"

    joblib.dump(pipeline, model_path)
    
    summary = {
        "dataset": str(dataset_path),
        "n_rows": int(len(df)),
        "n_features": int(X.shape[1]),
        "features": X.columns.tolist(),
        "test_metrics": metrics,
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "model_path": str(model_path),
    }

    if cv_results:
        cv_summary = {
            "n_splits": args.cv_splits,
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

    result_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print("\nTest Metrics:")
    for metric_name, value in metrics.items():
        print(f"  {metric_name}: {value:.4f}")
    
    if cv_results:
        print("\nCross-Validation Metrics (mean ± std):")
        for metric_name in ["accuracy", "f1", "precision", "recall", "roc_auc"]:
            mean_key = f"test_{metric_name}"
            if mean_key in cv_results:
                mean_val = cv_results[mean_key].mean()
                std_val = cv_results[mean_key].std()
                print(f"  {metric_name}: {mean_val:.4f} ± {std_val:.4f}")

    print(f"\nSaved: {result_path}")
    print(f"Model: {model_path}")


if __name__ == "__main__":
    main()
