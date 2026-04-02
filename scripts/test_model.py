"""Test joblib model dengan sample data."""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.tabular_features import build_tabular_features


def test_single_request(model_path: str, request_data: dict) -> dict:
    """Test model dengan 1 request.
    
    Args:
        model_path: Path ke joblib model
        request_data: Dict dengan kolom yg dibutuhkan (method, uri, status, dll)
    
    Returns:
        Dict dengan prediction result
    """
    # Load model
    print(f"[INFO] Loading model: {model_path}")
    model = joblib.load(model_path)
    print("[OK] Model loaded")
    
    # Create dataframe
    df = pd.DataFrame([request_data])
    print(f"\n[INPUT] Request data:")
    print(df)
    
    try:
        # Build features
        print(f"\n[INFO] Building features...")
        X = build_tabular_features(df)
        print(f"[OK] Features shape: {X.shape}")
        print(f"[OK] Features:\n{X}")
        
        # Predict
        print(f"\n[INFO] Making prediction...")
        pred = model.predict(X)[0]
        prob = model.predict_proba(X)[0, 1]
        
        result = {
            "is_attack": int(pred),
            "probability": float(prob),
            "confidence": "HIGH" if prob > 0.8 else ("MEDIUM" if prob > 0.6 else "LOW"),
        }
        
        print(f"\n[RESULT]")
        print(f"  is_attack: {result['is_attack']}")
        print(f"  probability: {result['probability']:.4f}")
        print(f"  confidence: {result['confidence']}")
        
        if result['is_attack'] == 1:
            print(f"\n⚠️  ATTACK DETECTED! Severity: {result['confidence']}")
        else:
            print(f"\n✅ Normal request")
        
        return result
        
    except Exception as e:
        print(f"[ERROR] {e}")
        raise


def main():
    """Test dengan sample requests."""
    model_path = "models/trained_models/tabular_xgboost.joblib"
    
    print("=" * 60)
    print("TESTING JOBLIB MODEL")
    print("=" * 60)
    
    # Sample 1: Normal request
    print("\n[TEST 1] Normal request")
    print("-" * 60)
    normal_request = {
        "method": "GET",
        "uri": "/index.php",
        "status": 200,
        "bytes_sent": 1024,
        "request_time": 0.05,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "user_agent_len": 50,
        "uri_len": 11,
        "severity": "INFO",
        "severity_score": 0,
        "rule_id": "",
        "matched_data": "",
        "is_blocked": False,
    }
    test_single_request(model_path, normal_request)
    
    # Sample 2: SQL Injection attempt
    print("\n\n[TEST 2] SQL Injection attempt")
    print("-" * 60)
    sqli_request = {
        "method": "POST",
        "uri": "/admin/login.php?id=1' OR '1'='1",
        "status": 403,
        "bytes_sent": 0,
        "request_time": 0.01,
        "user_agent": "curl/7.64.1",
        "user_agent_len": 12,
        "uri_len": 32,
        "severity": "CRITICAL",
        "severity_score": 4,
        "rule_id": "981173",
        "matched_data": "OR 1=1",
        "is_blocked": True,
    }
    test_single_request(model_path, sqli_request)
    
    # Sample 3: XSS attempt
    print("\n\n[TEST 3] XSS attempt")
    print("-" * 60)
    xss_request = {
        "method": "GET",
        "uri": "/search.php?q=<script>alert('xss')</script>",
        "status": 403,
        "bytes_sent": 0,
        "request_time": 0.02,
        "user_agent": "Firefox/90.0",
        "user_agent_len": 15,
        "uri_len": 42,
        "severity": "WARNING",
        "severity_score": 2,
        "rule_id": "941100",
        "matched_data": "<script>alert",
        "is_blocked": True,
    }
    test_single_request(model_path, xss_request)


if __name__ == "__main__":
    main()
