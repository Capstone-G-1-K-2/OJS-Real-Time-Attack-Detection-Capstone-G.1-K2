"""
Inference Example - Cara pakai model untuk predict real traffic.

Menunjukkan:
1. Minimal features yang dibutuhkan
2. CVE-specific features untuk accuracy
3. Contoh berbagai attack + normal traffic
"""

import pickle
import pandas as pd
from pathlib import Path

# Load model
print("[INFO] Loading trained XGBoost model...")
MODEL_PATH = "models/trained_models/modsec_xgb.pkl"
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

print("[OK] Model loaded\n")

# ============================================================================
# INFERENCE: Apa yang dibutuhkan? 18 Features
# ============================================================================

print("=" * 80)
print("REQUIRED FEATURES FOR INFERENCE (18 total)")
print("=" * 80)

features_required = {
    "Numeric": {
        "status": "HTTP response code (200, 403, 500, etc)",
        "bytes_sent": "Response body size in bytes",
        "request_time": "Request latency in seconds",
        "rule_count": "Number of ModSecurity rules triggered",
        "severity_score": "Max severity (0-5) from all rules",
        "user_agent_len": "Length of User-Agent header",
        "uri_len": "Length of URI/URL",
    },
    "Existing Attack Patterns": {
        "has_sqli_pattern": "1 if SQLi pattern detected, else 0",
        "has_xss_pattern": "1 if XSS pattern detected, else 0",
        "has_suspicious_path": "1 if /admin, /etc/passwd etc, else 0",
        "has_path_traversal": "1 if ../ or %2e%2e detected, else 0",
        "has_command_injection": "1 if ; cat, $(cmd) etc detected, else 0",
    },
    "CVE-Specific": {
        "has_cve_2022_24181": "1 if XSS in Host header (2.4.8-3.3.8)",
        "missing_csrf_token": "1 if no CSRF token in request",
        "has_suspicious_referer": "1 if Referer header missing",
        "has_cve_2024_xss_privesc": "1 if XSS + privilege escalation combined",
        "has_privesc_attempt": "1 if privilege escalation attempt",
        "has_cve_2021_32626": "1 if RCE file upload pattern (<2.3.7)",
    },
    "Text": {
        "method": "HTTP method (GET, POST, etc) - for pipeline",
        "uri": "Request URI - converted to 300 TF-IDF features internally",
    }
}

for category, features in features_required.items():
    print(f"\n{category} ({len(features)} features):")
    for feat, desc in features.items():
        print(f"  ✓ {feat:30} → {desc}")

print("\n" + "=" * 80)

# ============================================================================
# EXAMPLE 1: Attack - SQLi with all features
# ============================================================================

print("\nEXAMPLE 1: SQL INJECTION ATTACK (Full 18 Features)")
print("-" * 80)

attack_sqli = {
    "method": "POST",
    "uri": "/index.php/ojs-security/user/register?username=admin' OR '1'='1",
    "status": 403,
    "bytes_sent": 0,
    "request_time": 0.01,
    "rule_count": 3,           # 3 ModSec rules triggered
    "severity_score": 8,
    "user_agent_len": 65,
    "uri_len": 65,
    # Patterns
    "has_sqli_pattern": 1,      # SQLi detected in URI
    "has_xss_pattern": 0,
    "has_suspicious_path": 0,
    "has_path_traversal": 0,
    "has_command_injection": 0,
    # CVE-specific
    "has_cve_2022_24181": 0,           # No Host header XSS
    "missing_csrf_token": 1,            # POST without CSRF token
    "has_suspicious_referer": 1,        # No Referer header
    "has_cve_2024_xss_privesc": 0,      # Not XSS + privesc
    "has_privesc_attempt": 0,           # Not privesc
    "has_cve_2021_32626": 0,            # Not file upload
}

df_sqli = pd.DataFrame([attack_sqli])
pred_sqli = model.predict(df_sqli)[0]
prob_sqli = model.predict_proba(df_sqli)[0]

print("Input:")
for key, val in attack_sqli.items():
    print(f"  {key:30} = {val}")

print(f"\nPrediction:")
print(f"  Predicted class: {pred_sqli} (0=normal, 1=attack)")
print(f"  Attack probability: {prob_sqli[1]:.4f} ({prob_sqli[1]*100:.2f}%)")
print(f"  Result: {'[ATTACK]' if pred_sqli == 1 else '[NORMAL]'}")

# ============================================================================
# EXAMPLE 2: Attack - Path Traversal + CVE-2021-32626 (File Upload RCE)
# ============================================================================

print("\n\nEXAMPLE 2: RCE - FILE UPLOAD (CVE-2021-32626)")
print("-" * 80)

attack_rce = {
    "method": "POST",
    "uri": "/index.php/ojs-security/upload?file=shell.php%00.jpg",
    "status": 403,
    "bytes_sent": 0,
    "request_time": 0.02,
    "rule_count": 2,
    "severity_score": 9,  # Critical
    "user_agent_len": 50,
    "uri_len": 60,
    # Patterns
    "has_sqli_pattern": 0,
    "has_xss_pattern": 0,
    "has_suspicious_path": 0,
    "has_path_traversal": 0,
    "has_command_injection": 0,
    # CVE-specific (CRITICAL)
    "has_cve_2022_24181": 0,
    "missing_csrf_token": 1,
    "has_suspicious_referer": 1,
    "has_cve_2024_xss_privesc": 0,
    "has_privesc_attempt": 0,
    "has_cve_2021_32626": 1,  # ← FILE UPLOAD RCE DETECTED
}

df_rce = pd.DataFrame([attack_rce])
pred_rce = model.predict(df_rce)[0]
prob_rce = model.predict_proba(df_rce)[0]

print("Input:")
for key, val in attack_rce.items():
    print(f"  {key:30} = {val}")

print(f"\nPrediction:")
print(f"  Predicted class: {pred_rce} (0=normal, 1=attack)")
print(f"  Attack probability: {prob_rce[1]:.4f} ({prob_rce[1]*100:.2f}%)")
print(f"  CVE-2021-32626 detected: {attack_rce['has_cve_2021_32626']}")
print(f"  Result: {'[CRITICAL ATTACK]' if pred_rce == 1 else '[NORMAL]'}")

# ============================================================================
# EXAMPLE 3: Normal - Legitimate Login
# ============================================================================

print("\n\nEXAMPLE 3: LEGITIMATE LOGIN (Normal Traffic)")
print("-" * 80)

normal_login = {
    "method": "POST",
    "uri": "/index.php/ojs-security/login/signIn",
    "status": 302,  # Redirect (success)
    "bytes_sent": 512,
    "request_time": 0.08,
    "rule_count": 0,  # No rules triggered
    "severity_score": 0,
    "user_agent_len": 95,
    "uri_len": 37,
    # Patterns
    "has_sqli_pattern": 0,
    "has_xss_pattern": 0,
    "has_suspicious_path": 0,
    "has_path_traversal": 0,
    "has_command_injection": 0,
    # CVE-specific
    "has_cve_2022_24181": 0,
    "missing_csrf_token": 0,  # Has CSRF token
    "has_suspicious_referer": 0,  # Has Referer header
    "has_cve_2024_xss_privesc": 0,
    "has_privesc_attempt": 0,
    "has_cve_2021_32626": 0,
}

df_normal = pd.DataFrame([normal_login])
pred_normal = model.predict(df_normal)[0]
prob_normal = model.predict_proba(df_normal)[0]

print("Input:")
for key, val in normal_login.items():
    print(f"  {key:30} = {val}")

print(f"\nPrediction:")
print(f"  Predicted class: {pred_normal} (0=normal, 1=attack)")
print(f"  Attack probability: {prob_normal[1]:.4f} ({prob_normal[1]*100:.2f}%)")
print(f"  Result: {'[ATTACK]' if pred_normal == 1 else '[NORMAL]'}")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n\n" + "=" * 80)
print("SUMMARY - INFERENCE RESULTS")
print("=" * 80)

results = [
    ("SQLi Attack", pred_sqli, prob_sqli[1]),
    ("RCE/Upload", pred_rce, prob_rce[1]),
    ("Legit Login", pred_normal, prob_normal[1]),
]

print("\n{:<20} {:<15} {:<15}".format("Test Case", "Prediction", "Probability"))
print("-" * 50)
for name, pred, prob in results:
    label = "ATTACK" if pred == 1 else "NORMAL"
    print("{:<20} {:<15} {:<15.2%}".format(name, label, prob))

print("\n" + "=" * 80)
print("KEY INSIGHTS FOR INFERENCE")
print("=" * 80)
print("""
1. REQUIRED INPUT: 18 features (7 numeric + 5 patterns + 6 CVE + uri)
   
2. FEATURE SOURCE - Where to get them:
   ✓ From ModSecurity audit.log: status, bytes_sent, request_time, 
     rule_count, severity_score, rule_id
   ✓ From HTTP request: method, uri, user_agent_len
   ✓ Calculate: uri_len
   ✓ Pattern matching: has_sqli_pattern, has_xss_pattern, etc
   ✓ CVE detection: has_cve_2022_24181, missing_csrf_token, etc
   
3. QUICK INFERENCE STEPS:
   a) Extract request features (method, uri, status, etc)
   b) Run pattern detection (SQLi, XSS, path traversal, etc)
   c) Check CVE-specific patterns (Host header, CSRF, privesc, etc)
   d) Create DataFrame with all 18 features
   e) Call model.predict_proba() to get attack probability
   f) Threshold (default 0.5): prob >= 0.5 → ATTACK, else NORMAL
   
4. EXPECTED ACCURACY:
   ✓ With all 18 features: ~95% (ROC-AUC 0.9538)
   ✓ With partial features: ~90-92% (missing CVE features)
   
5. MINIMAL INFERENCE (if can't get all 18):
   Can use 12 features minimum, but accuracy drops 3-5%
   See prepare_dataset_from_raw_json_v2.py for full extraction
""")

print("\n[SUCCESS] Inference examples completed!")
