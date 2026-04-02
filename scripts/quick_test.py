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
model = joblib.load("models/trained_models/tabular_xgboost.joblib")

# Sample requests
test_cases = [
    {"name": "Normal - Homepage", "method": "GET", "uri": "/index.php"},
    {"name": "Attack - Bot scanning", "method": "GET", "uri": "/robots.txt"},
    {"name": "Normal - Upload", "method": "POST", "uri": "/upload.php"},
    {"name": "Attack - Admin path", "method": "GET", "uri": "/.git/config"},
    {"name": "Normal - Search", "method": "GET", "uri": "/search.php?q=test"},
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
    status = "🔴 ATTACK" if pred == 1 else "✅ NORMAL"
    print(f"\n{status}  |  {name}")
    print(f"  URI: {test['uri']}")
    print(f"  Probability: {prob:.4f}")
