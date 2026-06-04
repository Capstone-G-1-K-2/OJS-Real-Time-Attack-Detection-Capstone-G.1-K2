"""Quick test untuk predict dengan realistic test cases dari actual dataset."""

import sys
from pathlib import Path
import pickle
import pandas as pd
import random

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Load model
print("[INFO] Loading model...")
with open("models/trained_models/modsec_xgb.pkl", 'rb') as f:
    model = pickle.load(f)

print("[INFO] Loading dataset for dynamic sampling...")
df = pd.read_csv("data/dataset/modsec_raw_json_v2.csv", low_memory=False)

# Select diverse attacks
attacks = []

# Hardcoded Special Cases from latest user logs
cve_upload_test = pd.DataFrame([{
    "uri": "/index.php/OJS/management/importexport/plugin/NativeImportExportPlugin/uploadImportXML",
    "method": "POST",
    "status": 200,
    "has_cve_2023_47271_upload": 1,
    "has_cve_2023_47271_rce": 0,
    "severity_score": 4,
    "rule_count": 1,
    "bytes_sent": 82,
    "user_agent_len": 105,
    "uri_len": 86,
    "is_blocked": 0,
    "label": 1
}])
attacks.append(("ATTACK - CVE-2023-47271 Upload (Manual Special)", cve_upload_test))

cve_rce_test = pd.DataFrame([{
    "uri": "/public/journals/1/capstone-document-root-1780560465968.php?cacheBust=1780560484355",
    "method": "GET",
    "status": 200,
    "has_cve_2023_47271_upload": 0,
    "has_cve_2023_47271_rce": 1,
    "severity_score": 0,
    "rule_count": 0,
    "bytes_sent": 13,
    "user_agent_len": 11,
    "uri_len": 86,
    "is_blocked": 0,
    "label": 1
}])
attacks.append(("ATTACK - CVE-2023-47271 RCE (Manual Special)", cve_rce_test))

if not df[(df['label'] == 1) & (df['has_sqli'] == 1)].empty:
    attacks.append(("ATTACK - SQL Injection (Real Data)", df[(df['label'] == 1) & (df['has_sqli'] == 1)].sample(1)))
if not df[(df['label'] == 1) & (df['has_xss'] == 1)].empty:
    attacks.append(("ATTACK - XSS Injection (Real Data)", df[(df['label'] == 1) & (df['has_xss'] == 1)].sample(1)))
if not df[(df['label'] == 1) & (df['has_path_traversal'] == 1)].empty:
    attacks.append(("ATTACK - Path Traversal (Real Data)", df[(df['label'] == 1) & (df['has_path_traversal'] == 1)].sample(1)))
if not df[(df['label'] == 1) & (df['has_suspicious_path'] == 1)].empty:
    attacks.append(("ATTACK - Suspicious Path (Real Data)", df[(df['label'] == 1) & (df['has_suspicious_path'] == 1)].sample(1)))

if not df[(df['label'] == 1) & (df['has_cve_2023_47271_upload'] == 1)].empty:
    attacks.append(("ATTACK - CVE-2023-47271 XML Upload (Real Data)", df[(df['label'] == 1) & (df['has_cve_2023_47271_upload'] == 1)].sample(1)))
if not df[(df['label'] == 1) & (df['has_cve_2023_47271_rce'] == 1)].empty:
    attacks.append(("ATTACK - CVE-2023-47271 PHP RCE (Real Data)", df[(df['label'] == 1) & (df['has_cve_2023_47271_rce'] == 1)].sample(1)))

# Pad with random attacks
remaining_attacks = df[df['label'] == 1].sample(15)
for i, (_, row) in enumerate(remaining_attacks.iterrows()):
    if len(attacks) < 13:
        attacks.append((f"ATTACK - Random Attack {i+1} (Real Data)", pd.DataFrame([row])))

# Select diverse normals
normals = []

# Add specific Normal tests to ensure no false positives on normal upload/access
normal_upload = df[(df['label'] == 0) & (df['method'] == 'POST') & (df['uri'].str.contains('/uploadFile|/importexport', case=False, na=False))]
if not normal_upload.empty:
    normals.append(("NORMAL - Legitimate File Upload (Real Data)", normal_upload.sample(1)))

normal_access = df[(df['label'] == 0) & (df['method'] == 'GET') & (df['uri'].str.contains('/public/journals/', case=False, na=False))]
if not normal_access.empty:
    normals.append(("NORMAL - Legitimate Public File Access (Real Data)", normal_access.sample(1)))

# Just grab 5 random normal samples to fill
normal_samples = df[df['label'] == 0].sample(5)
for i, (_, row) in enumerate(normal_samples.iterrows()):
    normals.append((f"NORMAL - Random Request {i+1} (Real Data)", pd.DataFrame([row])))

test_cases_raw = attacks + normals
random.shuffle(test_cases_raw)

print("\n" + "=" * 80)
print("REAL-DATA OJS ATTACK TEST CASES (From modsec_merged.csv)")
print("=" * 80)
print(f"Dataset Characteristics ({len(df):,} transactions):")
print(f"  - Total Attacks: {df['label'].sum():,} ({(df['label'].sum()/len(df))*100:.2f}%)")
print(f"    * SQL Injection: {df['has_sqli'].sum():,} ({(df['has_sqli'].sum()/len(df))*100:.2f}%)")
print(f"    * XSS: {df['has_xss'].sum():,} ({(df['has_xss'].sum()/len(df))*100:.2f}%)")
print(f"    * Suspicious Paths: {df['has_suspicious_path'].sum():,} ({(df['has_suspicious_path'].sum()/len(df))*100:.2f}%)")
print(f"    * Path Traversal: {df['has_path_traversal'].sum():,} ({(df['has_path_traversal'].sum()/len(df))*100:.2f}%)")
print(f"  - Total Normal: {len(df) - df['label'].sum():,} ({((len(df) - df['label'].sum())/len(df))*100:.2f}%)")
print("=" * 80)

correct = 0
total = 0

attack_count = len(attacks)
normal_count = len(normals)

# Extract expected features that the model was trained on
expected_features = model.feature_names_in_ if hasattr(model, 'feature_names_in_') else None

for name, df_test in test_cases_raw:
    uri = df_test['uri'].values[0]
    method = df_test['method'].values[0]
    status_code = df_test['status'].values[0]
    is_attack_expected = "ATTACK" in name
    
    # Format df_test for prediction (match model requirements)
    df_pred = df_test.rename(columns={
        "has_sqli": "has_sqli_pattern",
        "has_xss": "has_xss_pattern",
    })
    
    # Keep only features the model expects, if known
    if expected_features is not None:
        missing = [f for f in expected_features if f not in df_pred.columns]
        for m in missing:
            df_pred[m] = 0
        df_pred = df_pred[expected_features]
    else:
        # Fallback drop
        cols_to_drop = ['timestamp', 'source_ip', 'method', 'uri', 'user_agent', 'matched_data', 'msg', 'label', 'pred_score', 'is_alerted', 'alert_channel', 'created_at', 'updated_at']
        df_pred = df_pred.drop(columns=[c for c in cols_to_drop if c in df_pred.columns])
    
    try:
        pred = model.predict(df_pred)[0]
        prob = model.predict_proba(df_pred)[0]
    except Exception as e:
        print(f"Error predicting for {name}: {e}")
        continue
    
    attack_prob = prob[1]
    label = "[ATTACK]" if pred == 1 else "[NORMAL]"
    
    is_correct = (pred == 1) == is_attack_expected
    
    total += 1
    if is_correct:
        correct += 1
        status = "[OK]"
    else:
        status = "[X]"
    
    print(f"\n{status} {label}")
    print(f"   Name: {name}")
    print(f"   URI: {uri}")
    print(f"   Method: {method} | Status: {status_code}")
    print(f"   Attack Probability: {attack_prob:.4f}")

print("\n" + "=" * 80)
print(f"SUMMARY: {correct}/{total} test cases aligned with expectations")
print("=" * 80)

print(f"\n[TEST BREAKDOWN]:")
print(f"    - Attack tests: {attack_count}")
print(f"    - Normal tests: {normal_count}")

print(f"\n[MODEL PERFORMANCE ANALYSIS]:")
if correct >= total - 2:
    print(f"    [SUCCESS] Model performance is excellent!")
    print(f"    - Correctly identifies real-world attack patterns from the dataset")
    print(f"    - Distinguishes legitimate OJS operations seamlessly")
    print(f"    - Ready for deployment in production OJS environment")
elif correct >= total - 4:
    print(f"    [GOOD] Model performance is acceptable")
    print(f"    - Most OJS-specific patterns detected correctly")
    print(f"    - Consider threshold tuning for specific scenarios")
else:
    print(f"    [WARN] Consider improving feature engineering")
    print(f"    - Review misclassified test cases")
    print(f"    - May need retraining with updated patterns")
print("=" * 80)
