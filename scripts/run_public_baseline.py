from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import mlflow
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC
from xgboost import XGBClassifier

# Ensure project root is importable when script is run as: python scripts/run_public_baseline.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.modsec_parser import load_dataset

TEXT_COLUMN_CANDIDATES = ["text", "request", "payload", "http_request", "message", "raw"]
LABEL_COLUMN_CANDIDATES = ["label", "target", "class", "is_attack", "attack"]
SAFE_TEXT_FALLBACK_COLUMNS = [
    "method",
    "uri",
    "path",
    "query",
    "query_string",
    "user_agent",
    "request_body",
    "body",
]


def find_column(columns: list[str], candidates: list[str]) -> str | None:
    columns_lower = {c.lower(): c for c in columns}
    for candidate in candidates:
        if candidate in columns_lower:
            return columns_lower[candidate]
    return None


def build_models(random_state: int) -> dict[str, Pipeline]:
    return {
        "random_forest": Pipeline(
            [
                ("tfidf", TfidfVectorizer(max_features=30000, ngram_range=(1, 2))),
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=300,
                        random_state=random_state,
                        n_jobs=-1,
                    ),
                ),
            ]
        ),
        "svm": Pipeline(
            [
                ("tfidf", TfidfVectorizer(max_features=30000, ngram_range=(1, 2))),
                ("clf", SVC(kernel="linear", probability=True, random_state=random_state)),
            ]
        ),
        "xgboost": Pipeline(
            [
                ("tfidf", TfidfVectorizer(max_features=30000, ngram_range=(1, 2))),
                (
                    "clf",
                    XGBClassifier(
                        n_estimators=300,
                        max_depth=6,
                        learning_rate=0.05,
                        subsample=0.9,
                        colsample_bytree=0.9,
                        objective="binary:logistic",
                        eval_metric="logloss",
                        random_state=random_state,
                    ),
                ),
            ]
        ),
    }


def evaluate_model(model: Pipeline, X_train: pd.Series, X_test: pd.Series, y_train: pd.Series, y_test: pd.Series) -> dict[str, float]:
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
    else:
        y_prob = y_pred

    return {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Baseline comparison on public HTTP dataset (RF, SVM, XGBoost).")
    parser.add_argument("--dataset", required=True, help="Path dataset (CSV atau folder/file raw log).")
    parser.add_argument("--text-col", default="", help="Nama kolom teks request/payload.")
    parser.add_argument("--label-col", default="", help="Nama kolom label biner (0/1).")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--output-dir", default="models/model_registry/public_baseline")
    parser.add_argument("--max-samples", type=int, default=0, help="Sampling maksimum baris untuk percepat eksperimen (0 = pakai semua).")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset tidak ditemukan: {dataset_path}")

    print(f"[INFO] Loading dataset from: {dataset_path}", flush=True)
    if dataset_path.suffix.lower() == ".csv":
        df = pd.read_csv(dataset_path)
    else:
        df = load_dataset(dataset_path)

    if df.empty:
        raise ValueError("Dataset kosong.")

    print(f"[INFO] Dataset loaded: {len(df)} rows, {len(df.columns)} columns", flush=True)

    if args.max_samples and args.max_samples > 0 and len(df) > args.max_samples:
        df = df.sample(n=args.max_samples, random_state=args.random_state)
        print(f"[INFO] Sampling applied: {len(df)} rows", flush=True)

    text_col = args.text_col or find_column(df.columns.tolist(), TEXT_COLUMN_CANDIDATES)
    label_col = args.label_col or find_column(df.columns.tolist(), LABEL_COLUMN_CANDIDATES)

    if not text_col:
        # Fallback aman: hindari leakage seperti status/blocked code/source metadata.
        text_parts: list[pd.Series] = []
        used_cols: list[str] = []
        for col in SAFE_TEXT_FALLBACK_COLUMNS:
            if col in df.columns:
                text_parts.append(df[col].astype(str))
                used_cols.append(col)

        if text_parts:
            combined = text_parts[0]
            for part in text_parts[1:]:
                combined = combined.str.cat(part, sep=" ")
            df["_text_auto"] = combined
            text_col = "_text_auto"
            print(f"[INFO] Auto text columns used: {used_cols}", flush=True)

    if not text_col or not label_col:
        raise ValueError(
            "Gagal mendeteksi kolom text/label otomatis. Gunakan --text-col dan --label-col."
        )

    X = df[text_col].astype(str)
    y = df[label_col].astype(int)

    if y.nunique() < 2:
        raise ValueError("Label harus punya minimal dua kelas (0 dan 1).")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    mlflow.set_experiment("public-http-baseline-comparison")
    results: list[dict[str, float | str]] = []
    best_model_name = ""
    best_f1 = -1.0

    models = build_models(args.random_state)
    for model_name, model in models.items():
        print(f"[INFO] Training model: {model_name}", flush=True)
        with mlflow.start_run(run_name=model_name):
            mlflow.log_params(
                {
                    "model": model_name,
                    "dataset": str(dataset_path),
                    "text_col": text_col,
                    "label_col": label_col,
                    "test_size": args.test_size,
                    "random_state": args.random_state,
                }
            )

            metrics = evaluate_model(model, X_train, X_test, y_train, y_test)
            mlflow.log_metrics(metrics)

            model_path = output_dir / f"{model_name}.joblib"
            joblib.dump(model, model_path)
            mlflow.log_artifact(str(model_path))

            row: dict[str, float | str] = {"model": model_name}
            row.update(metrics)
            results.append(row)

            if metrics["f1"] > best_f1:
                best_f1 = metrics["f1"]
                best_model_name = model_name
        print(f"[INFO] Finished model: {model_name} | f1={metrics['f1']:.4f}", flush=True)

    result_df = pd.DataFrame(results).sort_values("f1", ascending=False)
    result_csv = output_dir / "comparison_results.csv"
    result_df.to_csv(result_csv, index=False)

    summary = {
        "best_model": best_model_name,
        "best_f1": best_f1,
        "result_csv": str(result_csv),
        "models_saved_to": str(output_dir),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("Eksperimen baseline selesai.")
    print(result_df.to_string(index=False))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
