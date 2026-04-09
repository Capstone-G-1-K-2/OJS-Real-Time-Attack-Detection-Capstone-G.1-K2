#!/usr/bin/env python3
"""Daily retraining script dengan auto versioning."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from datetime import datetime

# Setup path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier
import pickle
import mlflow
import mlflow.sklearn

from src.preprocessing.modsec_parser import load_dataset
from src.utils.model_versioning import ModelVersionManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def compare_and_decide_version(
    new_version: int,
    new_metrics: dict,
    version_manager: ModelVersionManager,
    accuracy_threshold: float = 0.002,  # 0.2% drop allowed
    f1_threshold: float = 0.005,         # 0.5% F1 drop allowed
) -> tuple[int, str]:
    """
    Compare new version dengan current version dengan sophisticated logic.
    Detects jika accuracy drop adalah karena new attack pattern atau bad data.
    
    Logika:
    1. Cek accuracy
       - Jika new > current → USE NEW (clearly better)
       - Jika new < current:
         a. Cek F1-score dan Recall
         b. Jika F1/Recall stable/better → likely NEW ATTACK PATTERN → USE NEW ✅
         c. Jika F1/Recall jatuh drastis → likely BAD DATA → KEEP OLD ⚠️
    
    Args:
        new_version: Version number yang baru dibuat
        new_metrics: Metrics dari new version
        version_manager: ModelVersionManager instance
        accuracy_threshold: Berapa % accuracy drop yg diizinkan jika F1 stable (0.2%)
        f1_threshold: Berapa % F1 drop yg diizinkan absolute (0.5%)
    
    Returns:
        (version_to_use, decision_reason)
    """
    current_version = version_manager.get_current_version()
    versions = version_manager.list_all_versions()
    
    # Find current version metrics
    current_metrics = None
    for v in versions:
        if v['version'] == current_version:
            current_metrics = {
                'accuracy': v.get('accuracy', 0),
                'f1': v.get('f1_score', 0),
                'precision': v.get('precision', 0),
                'recall': v.get('recall', 0),
                'roc_auc': v.get('roc_auc', 0)
            }
            break
    
    if not current_metrics:
        logger.warning(f"  ⚠️  Current version metrics not found, using new version")
        return new_version, "Current version metrics not found"
    
    # Extract metrics
    new_acc = new_metrics['accuracy']
    new_f1 = new_metrics['f1']
    new_rec = new_metrics['recall']
    new_prec = new_metrics['precision']
    new_auc = new_metrics['roc_auc']
    
    current_acc = current_metrics['accuracy']
    current_f1 = current_metrics['f1']
    current_rec = current_metrics['recall']
    current_prec = current_metrics['precision']
    current_auc = current_metrics['roc_auc']
    
    acc_diff = new_acc - current_acc
    f1_diff = new_f1 - current_f1
    rec_diff = new_rec - current_rec
    prec_diff = new_prec - current_prec
    auc_diff = new_auc - current_auc
    
    logger.info("\n📊 SOPHISTICATED VERSION COMPARISON")
    logger.info(f"  Current v{current_version} vs New v{new_version}")
    logger.info(f"  ┌─ Accuracy: {current_acc:.4f} → {new_acc:.4f} ({acc_diff:+.4f})")
    logger.info(f"  ├─ F1-Score: {current_f1:.4f} → {new_f1:.4f} ({f1_diff:+.4f})")
    logger.info(f"  ├─ Recall  : {current_rec:.4f} → {new_rec:.4f} ({rec_diff:+.4f})")
    logger.info(f"  ├─ Precision: {current_prec:.4f} → {new_prec:.4f} ({prec_diff:+.4f})")
    logger.info(f"  └─ ROC-AUC : {current_auc:.4f} → {new_auc:.4f} ({auc_diff:+.4f})")
    
    # Decision Logic
    logger.info("\n🔍 ANALYSIS:")
    
    # Case 1: Accuracy improved
    if acc_diff >= 0:
        logger.info(f"  ✅ Accuracy improved → USE NEW v{new_version}")
        return new_version, f"Accuracy improved: {acc_diff:+.4f}"
    
    # Case 2: Accuracy dropped - analyze deeper
    else:
        logger.info(f"  ⚠️  Accuracy dropped: {acc_diff:+.4f}")
        
        # Sub-case 2a: F1 dan Recall stable/improved (likely NEW ATTACK PATTERN)
        f1_acceptable = f1_diff >= -f1_threshold
        recall_improved = rec_diff > 0
        auc_stable = auc_diff >= -0.003  # Allow 0.3% AUC drop
        
        if f1_acceptable and recall_improved:
            logger.info(f"  ✅ BUT: F1 is acceptable ({f1_diff:+.4f}) & Recall improved ({rec_diff:+.4f})")
            logger.info(f"  🎯 Likely NEW ATTACK PATTERN detected → USE NEW v{new_version}")
            reason = f"New attack pattern detected (Accuracy {acc_diff:+.4f}, but Recall {rec_diff:+.4f})"
            return new_version, reason
        
        # Sub-case 2b: AUC stable but drop is small (likely small data variance)
        elif auc_stable and abs(acc_diff) < accuracy_threshold:
            logger.info(f"  ✅ BUT: ROC-AUC stable ({auc_diff:+.4f}) & drop minimal ({acc_diff:+.4f})")
            logger.info(f"  📊 Likely normal variance → USE NEW v{new_version}")
            reason = f"Minimal accuracy drop within tolerance (Accuracy {acc_diff:+.4f}, AUC {auc_diff:+.4f})"
            return new_version, reason
        
        # Sub-case 2c: F1, Recall, AUC all dropped (likely BAD DATA)
        else:
            logger.info(f"  ❌ F1, Recall, AUC all degraded → likely BAD DATA")
            logger.info(f"  🚫 Keep CURRENT v{current_version} for safety")
            reason = f"Quality degradation detected (F1 {f1_diff:+.4f}, Recall {rec_diff:+.4f}, AUC {auc_diff:+.4f})"
            return current_version, reason


def train_and_save_model(
    df: pd.DataFrame,
    output_dir: str = "models/trained_models",
    version_number: int = None,
    auto_update_version: bool = True,
) -> tuple[str, int, dict, str]:
    """
    Train model dan simpan dengan versioning + MLflow logging + auto version decision.
    
    Alur:
    1. Build preprocessing pipeline (feature engineering)
    2. Split data train-test
    3. Train XGBoost
    4. Evaluate metrics
    5. Save model dengan nama versi
    6. Compare dengan current version
    7. Auto-decide: use new atau keep old
    8. Update current_version.txt jika auto_update_version=True
    9. Log ke MLflow
    10. Return metrics + decision
    
    Args:
        df: DataFrame dengan kolom label
        output_dir: Direktori menyimpan model
        version_number: Jika None, version manager akan assign versi berikutnya
        auto_update_version: Jika True, auto-update current_version.txt berdasarkan comparison
    
    Returns:
        (model_path, active_version, metrics, decision_reason)
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup MLflow
    mlflow.set_experiment("daily-retraining")
    
    with mlflow.start_run():
        logger.info("Step 1: Prepare data")
        # Pisahin features dan label
        if "label" not in df.columns:
            raise ValueError("DataFrame must have 'label' column")
        
        X = df.drop(columns=["label"])
        y = df["label"]
        
        logger.info(f"  Total samples: {len(df)}")
        logger.info(f"  Features: {X.shape[1]}")
        logger.info(f"  Attack samples: {(y==1).sum()}")
        logger.info(f"  Normal samples: {(y==0).sum()}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        logger.info(f"  Train/Test split: {len(X_train)}/{len(X_test)}")
        
        # Log data parameters ke MLflow
        mlflow.log_param("total_samples", len(df))
        mlflow.log_param("train_samples", len(X_train))
        mlflow.log_param("test_samples", len(X_test))
        mlflow.log_param("attack_samples", int((y==1).sum()))
        mlflow.log_param("normal_samples", int((y==0).sum()))
        mlflow.log_param("n_features", X.shape[1])
        
        logger.info("Step 2: Build preprocessing pipeline")
        numeric_features = [
            "status", "bytes_sent", "request_time", "rule_count",
            "severity_score", "user_agent_len", "uri_len",
            "has_sqli_pattern", "has_xss_pattern", "has_suspicious_path"
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
        
        # Log model hyperparameters
        model_params = {
            "n_estimators": 300,
            "max_depth": 7,
            "learning_rate": 0.1,
            "random_state": 42,
        }
        mlflow.log_params(model_params)
        
        model = XGBClassifier(
            n_estimators=300,
            max_depth=7,
            learning_rate=0.1,
            random_state=42,
            n_jobs=-1,
            verbose=0,
        )
        
        pipeline = Pipeline([
            ("preprocessor", preprocessor),
            ("model", model),
        ])
        logger.info("  ✓ Pipeline created")
        
        logger.info("Step 3: Train model")
        pipeline.fit(X_train, y_train)
        logger.info("  ✓ Training complete")
        
        logger.info("Step 4: Evaluate on test set")
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_prob)
        
        metrics = {
            "accuracy": float(accuracy),
            "f1": float(f1),
            "precision": float(precision),
            "recall": float(recall),
            "roc_auc": float(roc_auc),
        }
        
        logger.info(f"  Accuracy: {accuracy:.4f}")
        logger.info(f"  F1-Score: {f1:.4f}")
        logger.info(f"  Precision: {precision:.4f}")
        logger.info(f"  Recall: {recall:.4f}")
        logger.info(f"  ROC-AUC: {roc_auc:.4f}")
        
        # Log metrics ke MLflow
        mlflow.log_metrics(metrics)
        
        # Log classification report
        class_report = classification_report(y_test, y_pred, output_dict=True)
        mlflow.log_dict(class_report, "classification_report.json")
        
        logger.info("Step 5: Save model dengan versioning")
        version_manager = ModelVersionManager(model_dir=str(output_dir))
        
        # Create new version entry
        new_version = version_manager.create_new_version(
            accuracy=accuracy,
            f1_score=f1,
            precision=precision,
            recall=recall,
            data_samples=len(X_train),
            notes=f"Daily retrain on {datetime.now().strftime('%Y-%m-%d')}"
        )
        
        # Save model file dengan versi
        model_path = version_manager.get_model_path(new_version)
        with open(model_path, 'wb') as f:
            pickle.dump(pipeline, f)
        logger.info(f"  ✓ Model saved: {model_path}")
        logger.info(f"  ✓ Version: {new_version}")
        
        # Log model version ke MLflow
        mlflow.set_tag("model_version", new_version)
        mlflow.set_tag("timestamp", datetime.now().isoformat())
        
        # Save model artifact ke MLflow
        mlflow.sklearn.log_model(pipeline, "xgboost_pipeline")
        
        # Also save latest metrics
        metrics_file = output_dir / "modsec_metrics.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"  ✓ Metrics saved: {metrics_file}")
        
        # Log metrics file as artifact
        mlflow.log_artifact(str(metrics_file))
        
        logger.info("  ✓ MLflow logging complete")
        
        logger.info("Step 6: Compare dengan current version dan auto-decide")
        # Compare versions dengan sophisticated logic
        active_version, decision_reason = compare_and_decide_version(
            new_version=new_version,
            new_metrics=metrics,
            version_manager=version_manager,
            accuracy_threshold=0.002,  # Allow 0.2% accuracy drop jika F1 stable
            f1_threshold=0.005,         # Allow 0.5% F1 drop
        )
        
        # Auto-update current version jika berbeda
        if auto_update_version and active_version != version_manager.get_current_version():
            logger.info(f"\n📝 Updating current_version.txt to v{active_version}")
            version_manager.rollback_to_version(active_version)
            logger.info(f"  ✓ Version updated: {active_version}")
        
        mlflow.set_tag("active_version", active_version)
        mlflow.set_tag("decision", decision_reason)
    
    return str(model_path), active_version, metrics, decision_reason


def main():
    """Main retraining function untuk daily scheduling."""
    parser = argparse.ArgumentParser(description="Daily model retraining")
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to combined dataset (old + new data)"
    )
    parser.add_argument(
        "--output-dir",
        default="models/trained_models",
        help="Output directory for models"
    )
    
    args = parser.parse_args()
    
    logger.info("="*60)
    logger.info("DAILY MODEL RETRAINING")
    logger.info("="*60)
    logger.info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Load data
        logger.info(f"\nLoading dataset: {args.dataset}")
        df = pd.read_csv(args.dataset) if args.dataset.endswith('.csv') else load_dataset(args.dataset)
        
        if df.empty:
            raise ValueError("Dataset kosong!")
        
        logger.info(f"✓ Loaded {len(df)} samples\n")
        
        # Train and save
        model_path, active_version, metrics, decision = train_and_save_model(
            df,
            output_dir=args.output_dir,
            auto_update_version=True  # Auto-decide dan update current version
        )
        
        logger.info("\n" + "="*60)
        logger.info("✓ RETRAINING COMPLETE!")
        logger.info("="*60)
        logger.info(f"Model path: {model_path}")
        logger.info(f"Metrics: Accuracy={metrics['accuracy']:.4f}, F1={metrics['f1']:.4f}")
        logger.info(f"Active Version: v{active_version}")
        logger.info(f"Decision: {decision}")
        logger.info(f"NextStep: Restart API server to load v{active_version}")
        logger.info("="*60 + "\n")
        
        return 0
    
    except Exception as e:
        logger.error(f"✗ RETRAINING FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
