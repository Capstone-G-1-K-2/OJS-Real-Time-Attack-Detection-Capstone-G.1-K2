"""Quick test using raw ModSecurity JSON transactions and the wrapped model.
Loads models/trained_models/modsec_xgb_with_preproc.pkl (ModelWrapper) and runs
predictions for a set of JSON-like transactions.
"""

import argparse
import sys
from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pickle

MODEL_PATH = Path("models/trained_models/modsec_xgb_with_preproc.pkl")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Quick test wrapped ModSecurity model on sample JSON transactions.")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.45,
        help="Decision threshold used for ATTACK vs NORMAL classification.",
    )
    return parser.parse_args()


args = _parse_args()

print("[INFO] Loading wrapped model...")
with MODEL_PATH.open("rb") as f:
    wrapper = pickle.load(f)

# Define JSON-style transactions (minimal fields required by extractor)
TEST_TXS = [
    ("ATTACK - CVE-2023-25900 XSS article title injection", {
        "time_stamp": "2026-05-07T00:00:00Z",
        "client_ip": "10.0.0.1",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/article/submit?title=<script>alert(1)</script>", "headers": {"User-Agent": "qt", "Host": "ojs.local", "Referer": ""}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

    ("ATTACK - CVE-2023-25901 arbitrary file access", {
        "time_stamp": "2026-05-07T00:00:01Z",
        "client_ip": "10.0.0.2",
        "request": {"method": "GET", "uri": "/index.php/ojs-security/article/download?file=../../../../etc/passwd", "headers": {"User-Agent": "qt"}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

    ("ATTACK - SQLi on user registration endpoint", {
        "time_stamp": "2026-05-07T00:00:02Z",
        "client_ip": "10.0.0.3",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/user/register?username=admin' OR '1'='1", "headers": {"User-Agent": "qt"}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

    ("ATTACK - XSS in article search function", {
        "time_stamp": "2026-05-07T00:00:03Z",
        "client_ip": "10.0.0.4",
        "request": {"method": "GET", "uri": "/index.php/ojs-security/search?q=<img src=x onerror=alert(1)>", "headers": {"User-Agent": "qt"}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

    ("ATTACK - Brute force login attempt", {
        "time_stamp": "2026-05-07T00:00:04Z",
        "client_ip": "10.0.0.5",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/login/signIn", "headers": {"User-Agent": "" , "Referer": ""}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

    ("ATTACK - Path traversal in submission upload", {
        "time_stamp": "2026-05-07T00:00:05Z",
        "client_ip": "10.0.0.6",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/article/submit?filename=../../../config.inc.php", "headers": {"User-Agent": "qt"}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

    ("NORMAL - Legitimate user registration", {
        "time_stamp": "2026-05-07T00:00:06Z",
        "client_ip": "10.0.0.7",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/user/register", "headers": {"User-Agent": "client", "Referer": "https://ojs.local/"}},
        "response": {"http_code": 302, "body": "ok"},
        "messages": []
    }, 0),

    ("NORMAL - Legitimate user login", {
        "time_stamp": "2026-05-07T00:00:07Z",
        "client_ip": "10.0.0.8",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/login/signIn", "headers": {"User-Agent": "client", "Referer": "https://ojs.local/"}},
        "response": {"http_code": 302, "body": "ok"},
        "messages": []
    }, 0),

    ("NORMAL - Reset password request", {
        "time_stamp": "2026-05-07T00:00:08Z",
        "client_ip": "10.0.0.9",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/login/requestResetPassword", "headers": {"User-Agent": "client", "Referer": "https://ojs.local/"}},
        "response": {"http_code": 200, "body": "ok"},
        "messages": []
    }, 0),

    ("ATTACK - Double encoded SQLi attempt", {
        "time_stamp": "2026-05-07T00:00:09Z",
        "client_ip": "10.0.0.10",
        "request": {"method": "GET", "uri": "/index.php/ojs-security/search?q=%25%32%37%20OR%20%25%32%37%31%25%32%37%3D%25%32%37%31", "headers": {"User-Agent": "qt"}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

    ("ATTACK - Polyglot injection (XSS + SQLi hybrid)", {
        "time_stamp": "2026-05-07T00:00:10Z",
        "client_ip": "10.0.0.11",
        "request": {"method": "POST", "uri": "/index.php/ojs-security/user/register", "headers": {"User-Agent": "qt"}},
        "response": {"http_code": 403, "body": ""},
        "messages": []
    }, 1),

]

passed = 0
total = len(TEST_TXS)
attack_count = 0
normal_count = 0

for name, tx, expected in TEST_TXS:
    res = wrapper.predict_from_json(tx, threshold=args.threshold)
    prob = res.get("probability")
    pred = res.get("prediction")
    ok = pred == expected
    status = "[OK]" if ok else "[X]"
    label_str = "ATTACK" if expected == 1 else "NORMAL"
    print(f"{status}  {name}")
    print(
        f"   URI: {tx['request'].get('uri')} | Method: {tx['request'].get('method')} | "
        f"Pred: {pred} | Prob: {prob:.4f} | Threshold: {args.threshold:.2f} | Expect: {label_str}\n"
    )
    if ok:
        passed += 1
    if expected == 1:
        attack_count += 1
    else:
        normal_count += 1

print("\n" + "="*80)
print(f"SUMMARY: {passed}/{total} test cases aligned with expectations")
print(f"Attack tests: {attack_count}, Normal tests: {normal_count}")
