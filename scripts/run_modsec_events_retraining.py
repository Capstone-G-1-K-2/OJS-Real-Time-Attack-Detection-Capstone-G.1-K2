#!/usr/bin/env python3
"""Export modsec_events and train a new model for scheduled retraining."""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.export_modsec_events_for_retraining import export_events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export modsec_events and train a timestamped model."
    )
    parser.add_argument(
        "--dataset-output",
        default=None,
        help=(
            "Optional CSV output path. Default: "
            "data/processed/retraining_dataset_YYMMDDHHMMSS.csv"
        ),
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test set fraction passed to run_modsec_training.py.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed passed to run_modsec_training.py.",
    )
    parser.add_argument(
        "--cv-splits",
        type=int,
        default=5,
        help="Number of CV folds or iterations.",
    )
    parser.add_argument(
        "--cv-method",
        choices=["kfold", "shuffle"],
        default="kfold",
        help="Cross-validation method.",
    )
    parser.add_argument(
        "--no-cv",
        action="store_true",
        help="Skip cross-validation.",
    )
    parser.add_argument(
        "--use-smote",
        action="store_true",
        help="Apply SMOTE oversampling to the training set.",
    )
    parser.add_argument(
        "--use-optuna",
        action="store_true",
        help="Run Optuna tuning.",
    )
    parser.add_argument(
        "--optuna-trials",
        type=int,
        default=None,
        help="Number of Optuna trials. Defaults to config value.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    os.chdir(PROJECT_ROOT)

    from scripts.run_modsec_training import train
    from src.utils.config import get_config

    timestamp = datetime.now().strftime("%y%m%d%H%M%S")
    dataset_path = Path(
        args.dataset_output
        or f"data/processed/retraining_dataset_{timestamp}.csv"
    )
    model_path = Path(
        f"models/trained_models/model_{timestamp}.pkl"
    )
    metrics_path = Path(
        f"models/trained_models/model_{timestamp}_metrics.json"
    )

    print("=" * 60)
    print("MODSEC EVENTS RETRAINING")
    print("=" * 60)
    print(f"Dataset output: {dataset_path}")
    print(f"Model output  : {model_path}")
    print(f"Metrics output: {metrics_path}")

    started_at = time.monotonic()

    exported_rows = export_events(
        output_path=dataset_path
    )

    print(f"[INFO] Exported rows: {exported_rows}")

    if exported_rows == 0:
        raise SystemExit("No modsec_events rows available for retraining.")

    config = get_config()
    optuna_trials = (
        args.optuna_trials
        if args.optuna_trials is not None
        else config.config.get("training", {}).get("optuna_trials", 25)
    )

    threshold = config.get_threshold()
    env_threshold = os.getenv("MODEL_INFERENCE_THRESHOLD")
    if env_threshold:
        threshold = float(env_threshold)

    summary = train(
        dataset_path=str(dataset_path),
        model_output=str(model_path),
        metrics_output=str(metrics_path),
        test_size=args.test_size,
        random_state=args.random_state,
        n_splits=args.cv_splits,
        run_cv=not args.no_cv,
        use_smote=args.use_smote,
        use_optuna=args.use_optuna,
        optuna_trials=optuna_trials,
        cv_method=args.cv_method,
        mlflow_run_name=f"cron-retraining-{timestamp}",
        threshold=threshold,
        config=config,
    )

    elapsed_seconds = int(
        round(time.monotonic() - started_at)
    )

    print("\n" + "=" * 60)
    print("RETRAINING COMPLETE")
    print("=" * 60)
    print(f"Saved model    : {model_path}")
    print(f"Saved metrics  : {metrics_path}")
    print(f"Dataset rows   : {exported_rows}")
    print(f"Time needed    : {elapsed_seconds} seconds")

    metrics = summary["test_metrics"]
    print(f"Accuracy       : {metrics['accuracy']:.4f}")
    print(f"F1             : {metrics['f1']:.4f}")
    print(f"Precision      : {metrics['precision']:.4f}")
    print(f"Recall         : {metrics['recall']:.4f}")
    print(f"ROC-AUC        : {metrics['roc_auc']:.4f}")


if __name__ == "__main__":
    main()
