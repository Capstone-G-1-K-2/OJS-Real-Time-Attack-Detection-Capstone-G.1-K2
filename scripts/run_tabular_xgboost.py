from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
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

    y = pd.to_numeric(df[args.label_col], errors="coerce").fillna(0).astype(int)
    X = build_tabular_features(df)

    if y.nunique() < 2:
        raise ValueError("Label harus punya minimal dua kelas (0 dan 1).")

    cat_cols = ["method"] if "method" in X.columns else []
    num_cols = [c for c in X.columns if c not in cat_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
            ("num", "passthrough", num_cols),
        ],
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

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "tabular_xgboost.joblib"
    result_path = output_dir / "result.json"

    joblib.dump(pipeline, model_path)
    result_path.write_text(
        json.dumps(
            {
                "dataset": str(dataset_path),
                "n_rows": int(len(df)),
                "features": X.columns.tolist(),
                "metrics": metrics,
                "model_path": str(model_path),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print("[INFO] Done.")
    print(json.dumps(metrics, indent=2))
    print(f"[INFO] Saved: {result_path}")


if __name__ == "__main__":
    main()
