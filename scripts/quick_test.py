"""Quick test untuk predict 1 request."""

import sys
from pathlib import Path

import joblib
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.tabular_features import build_tabular_features

# Load model
print("[INFO] Loading model...")
# Use modsec model (better probability calibration & more reliable inference)
model = joblib.load("models/trained_models/modsec_xgb.joblib")

# Sample requests
test_cases = [
    # Normal cases
    {"name": "Normal - Homepage", "method": "GET", "uri": "/index.php"},
    {"name": "Normal - Upload", "method": "POST", "uri": "/upload.php"},
    {"name": "Normal - Search", "method": "GET", "uri": "/search.php?q=test"},
    
    # Attack cases from training data (realistic)
    {"name": "Attack - Bot scanning (minimal)", "method": "GET", "uri": "/robots.txt"},
    {"name": "Attack - Bot scanning (detected)", "method": "GET", "uri": "/robots.txt", "severity_score": 4},
    {"name": "Attack - XML-RPC (minimal)", "method": "POST", "uri": "/xmlrpc.php"},
    {"name": "Attack - XML-RPC (detected)", "method": "POST", "uri": "/xmlrpc.php", "severity_score": 4},
    
    # Complete request examples
    {
        "name": "Complete - Normal OJS Request",
        "method": "GET",
        "uri": "/index.php/journal/article/view/1024",
        "status": 200,
        "bytes_sent": 2048,
        "request_time": 0.08,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "user_agent_len": 60,
        "uri_len": 35,
        "severity": "INFO",
        "severity_score": 0,
        "rule_id": "",
        "matched_data": "",
        "is_blocked": False,
    },
    {
        "name": "Complete - Suspicious Admin Access",
        "method": "GET",
        "uri": "/wp-admin/admin.php",
        "status": 403,
        "bytes_sent": 0,
        "request_time": 0.02,
        "user_agent": "curl/7.64.1",
        "user_agent_len": 11,
        "uri_len": 20,
        "severity": "CRITICAL",
        "severity_score": 4,
        "rule_id": "933150",
        "matched_data": "",
        "is_blocked": True,
    },
]

print("\n" + "=" * 60)
print("TESTING JOBLIB MODEL")
print("=" * 60)

for test in test_cases:
    name = test.pop("name")
    
    # Create dataframe
    df = pd.DataFrame([test])
    
    # Extract features
    X = build_tabular_features(df)
    
    # Predict
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0, 1]
    
    # Display
    status = "[ATTACK]" if pred == 1 else "[NORMAL]"
    print(f"\n{status}  |  {name}")
    print(f"  URI: {test['uri']}")
    print(f"  Probability: {prob:.4f}")
