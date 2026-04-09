"""Analyze why POST to robots.txt is flagged as attack."""

import sys
from pathlib import Path

import pickle
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.tabular_features import build_tabular_features

with open("models/trained_models/modsec_xgb.pkl", 'rb') as f:
    model = pickle.load(f)

test_cases = [
    {"name": "GET /robots.txt (Normal)", "method": "GET", "uri": "/robots.txt"},
    {"name": "POST /robots.txt (Suspicious)", "method": "POST", "uri": "/robots.txt"},
    {"name": "POST /search.php (Normal)", "method": "POST", "uri": "/search.php?q=test"},
    {"name": "POST /.git/config (Attack)", "method": "POST", "uri": "/.git/config"},
]

print("FEATURE ANALYSIS:")
print("=" * 70)

for test in test_cases:
    name = test.pop("name")
    df = pd.DataFrame([test])
    X = build_tabular_features(df)
    
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0, 1]
    status = "[ATTACK]" if pred == 1 else "[NORMAL]"
    
    # Show features
    print(f"\n{status} {name}")
    print(f"  Probability: {prob:.4f}")
    print(f"  Features:")
    for col in X.columns[:10]:
        val = X[col].iloc[0]
        print(f"    - {col}: {val}")
