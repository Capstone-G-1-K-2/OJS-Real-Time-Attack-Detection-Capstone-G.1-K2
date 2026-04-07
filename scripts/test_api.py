#!/usr/bin/env python3
"""Test script for API endpoints (standalone, no server needed)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Setup path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.api.models import LogRequest, BatchLogRequest
from src.pipeline.predictor import PredictionPipeline
import pandas as pd


async def test_single_prediction():
    """Test single log prediction."""
    print("\n" + "="*50)
    print("TEST 1: Single Prediction")
    print("="*50)
    
    pipeline = PredictionPipeline(
        model_path=str(PROJECT_ROOT / "models/trained_models/modsec_xgb.joblib")
    )
    
    # Normal request
    normal_log = pd.DataFrame([{
        "method": "GET",
        "uri": "/index.php/",
        "status": 200,
        "bytes_sent": 1024,
        "request_time": 0.05,
        "user_agent": "Mozilla/5.0",
        "rule_count": 0,
        "severity_score": 0,
    }])
    
    result = pipeline.predict(normal_log)
    print(f"\n✓ Normal request:")
    print(f"  Prediction: {'ATTACK' if result['predictions'][0] else 'NORMAL'}")
    print(f"  Probability: {result['probabilities'][0]:.4f}")
    
    # Suspicious request
    suspicious_log = pd.DataFrame([{
        "method": "POST",
        "uri": "/index.php/admin' OR '1'='1",
        "status": 403,
        "bytes_sent": 512,
        "request_time": 0.5,
        "user_agent": "curl/7.0",
        "rule_count": 3,
        "severity_score": 7.5,
    }])
    
    result = pipeline.predict(suspicious_log)
    print(f"\n✓ Suspicious request:")
    print(f"  Prediction: {'ATTACK' if result['predictions'][0] else 'NORMAL'}")
    print(f"  Probability: {result['probabilities'][0]:.4f}")


async def test_batch_prediction():
    """Test batch predictions."""
    print("\n" + "="*50)
    print("TEST 2: Batch Prediction")
    print("="*50)
    
    pipeline = PredictionPipeline(
        model_path=str(PROJECT_ROOT / "models/trained_models/modsec_xgb.joblib")
    )
    
    logs = pd.DataFrame([
        {
            "method": "GET",
            "uri": "/index.php/",
            "status": 200,
            "bytes_sent": 1024,
            "request_time": 0.05,
            "user_agent": "Mozilla/5.0",
            "rule_count": 0,
            "severity_score": 0,
        },
        {
            "method": "POST",
            "uri": "/index.php/article/submit",
            "status": 200,
            "bytes_sent": 2048,
            "request_time": 0.15,
            "user_agent": "Mozilla/5.0",
            "rule_count": 0,
            "severity_score": 0,
        },
        {
            "method": "GET",
            "uri": "/admin.php",
            "status": 403,
            "bytes_sent": 512,
            "request_time": 0.02,
            "user_agent": "curl/7.0",
            "rule_count": 2,
            "severity_score": 5.0,
        },
    ])
    
    result = pipeline.predict(logs)
    
    print(f"\n✓ Processed {len(logs)} logs:")
    print(f"  Total predictions: {len(result['predictions'])}")
    print(f"  Attacks: {sum(result['predictions'])}")
    print(f"  Normal: {len(result['predictions']) - sum(result['predictions'])}")
    
    if result['attacks']:
        print(f"\n  Detected attacks:")
        for attack in result['attacks']:
            print(f"    - {attack['method']} {attack['uri']} (prob: {attack['probability']:.4f})")


def test_models_loaded():
    """Test if models are loaded."""
    print("\n" + "="*50)
    print("TEST 0: Model Loading")
    print("="*50)
    
    model_path = PROJECT_ROOT / "models/trained_models/modsec_xgb.joblib"
    
    if model_path.exists():
        print(f"✓ Model file exists: {model_path}")
        pipeline = PredictionPipeline(model_path=str(model_path))
        if pipeline.model is not None:
            print(f"✓ Model loaded successfully")
            print(f"  Model type: {type(pipeline.model).__name__}")
        else:
            print(f"✗ Model failed to load")
    else:
        print(f"✗ Model file not found: {model_path}")


async def main():
    """Run all tests."""
    print("\n" + "█"*50)
    print("OJS Attack Detection - API Test Suite")
    print("█"*50)
    
    try:
        test_models_loaded()
        await test_single_prediction()
        await test_batch_prediction()
        
        print("\n" + "█"*50)
        print("✓ All tests completed!")
        print("█"*50)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
