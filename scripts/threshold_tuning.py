"""Threshold tuning analysis - find optimal decision boundary."""

import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.modsec_parser import load_dataset


def main():
    print("\n[INFO] Loading model...")
    with open("models/trained_models/modsec_xgb.pkl", 'rb') as f:
        model = pickle.load(f)

    print("[INFO] Loading dataset...")
    df = load_dataset("data/dataset/modsec_raw_json_v2.csv")
    
    # Prepare data
    df = df.rename(columns={
        'has_sqli': 'has_sqli_pattern',
        'has_xss': 'has_xss_pattern',
    })
    
    for col in ['rule_count', 'has_suspicious_path', 'has_sqli_pattern', 'has_xss_pattern', 
                'has_path_traversal', 'has_command_injection']:
        if col not in df.columns:
            df[col] = 0
    
    X = df.drop(columns=['label'])
    y = df['label'].astype(int)
    
    # Same split as training
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Get probabilities
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    print("\n" + "="*70)
    print("THRESHOLD TUNING ANALYSIS")
    print("="*70)
    print(f"Test set size: {len(X_test)} ({y_test.sum()} attacks, {(y_test==0).sum()} normal)")
    print()
    
    # Test thresholds
    thresholds = np.arange(0.1, 1.0, 0.1)
    results = []
    
    for threshold in thresholds:
        y_pred = (y_pred_proba >= threshold).astype(int)
        
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        false_alarm_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        miss_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        results.append({
            'threshold': threshold,
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
            'recall': recall,
            'precision': precision,
            'f1': f1,
            'false_alarm_rate': false_alarm_rate,
            'miss_rate': miss_rate,
        })
        
        print(f"[Threshold: {threshold:.1f}]")
        print(f"  Confusion Matrix: TP={tp:4d} FP={fp:4d} TN={tn:4d} FN={fn:4d}")
        print(f"  Recall:           {recall:6.2%}  (catch {recall:.1%} of attacks)")
        print(f"  Precision:        {precision:6.2%}  ({precision:.1%} alerts are real)")
        print(f"  F1-Score:         {f1:.4f}")
        print(f"  False Alarm Rate: {false_alarm_rate:6.2%}  ({int(fp)} false per {fp+tn} normal)")
        print(f"  Miss Rate:        {miss_rate:6.2%}  (miss {miss_rate:.1%} of attacks)")
        print()
    
    # Summary
    print("="*70)
    print("RECOMMENDATION")
    print("="*70)
    
    df_results = pd.DataFrame(results)
    
    # Find best for different goals
    best_balanced = df_results.iloc[(df_results['f1']).argmax()]
    best_recall = df_results.iloc[(df_results['recall']).argmax()]
    best_precision = df_results.iloc[(df_results['precision']).argmax()]
    
    print()
    print("Best for BALANCED performance (F1):")
    print(f"  Threshold: {best_balanced['threshold']:.1f}")
    print(f"  Recall: {best_balanced['recall']:.2%}, Precision: {best_balanced['precision']:.2%}")
    print(f"  False Alarm Rate: {best_balanced['false_alarm_rate']:.2%}")
    
    print()
    print("Best for CATCHING ATTACKS (High Recall):")
    print(f"  Threshold: {best_recall['threshold']:.1f}")
    print(f"  Recall: {best_recall['recall']:.2%}, Precision: {best_recall['precision']:.2%}")
    print(f"  False Alarm Rate: {best_recall['false_alarm_rate']:.2%}")
    
    print()
    print("Best for MINIMIZING FALSE ALARMS (High Precision):")
    print(f"  Threshold: {best_precision['threshold']:.1f}")
    print(f"  Recall: {best_precision['recall']:.2%}, Precision: {best_precision['precision']:.2%}")
    print(f"  False Alarm Rate: {best_precision['false_alarm_rate']:.2%}")
    
    print()
    print("="*70)
    print("QUICK COMPARISON TABLE")
    print("="*70)
    print()
    print("Threshold | Recall  | Precision | False Alarm | Miss Rate | F1-Score")
    print("-" * 70)
    for _, row in df_results.iterrows():
        print(f"  {row['threshold']:.1f}     | {row['recall']:6.2%} | {row['precision']:9.2%} | "
              f"{row['false_alarm_rate']:10.2%} | {row['miss_rate']:8.2%} | {row['f1']:.4f}")
    
    print()
    print("See docs/THRESHOLD_TUNING.md for detailed recommendations")
    print()


if __name__ == "__main__":
    main()
