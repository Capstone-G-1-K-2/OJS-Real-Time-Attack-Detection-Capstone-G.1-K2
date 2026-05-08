#!/usr/bin/env python3
"""
main.py - OJS WAF Real-Time Inference
Membaca audit.log ModSecurity, ekstrak field, dan prediksi via model pipeline
"""

import json
import time
import os
import pickle
import pandas as pd
from datetime import datetime

LOG_PATH = "/var/log/modsecurity/audit.log"
MODEL_PATH = "/app/model.pkl"

LABEL_MAP = {
    0: "Normal",
    1: "Malicious"
}

# ── Load model ──────────────────────────────────────────────────────────────
def load_model(path):
    print(f"[*] Loading model from {path}...")
    with open(path, "rb") as f:
        model = pickle.load(f)
    print(f"[*] Model loaded: {type(model)}")
    return model

# ── Extract fields dari audit log entry ─────────────────────────────────────
def extract_input(entry: dict) -> dict:
    t = entry.get("transaction", entry)  # support both formats

    # Request fields
    request = t.get("request", {})
    headers = request.get("headers", {})
    method  = request.get("method", "GET")
    uri     = request.get("uri", "/")

    # Response fields
    response    = t.get("response", {})
    http_code   = response.get("http_code", 0)
    body        = response.get("body", "")

    # Messages (rules triggered)
    messages = t.get("messages", [])

    # Metadata
    time_stamp = t.get("time_stamp", datetime.utcnow().isoformat() + "Z")
    client_ip  = t.get("client_ip", "0.0.0.0")

    return {
        "time_stamp": time_stamp,
        "client_ip":  client_ip,
        "request": {
            "method": method,
            "uri":    uri,
            "headers": {
                "User-Agent": headers.get("User-Agent", headers.get("user-agent", "")),
                "Host":       headers.get("Host", headers.get("host", "")),
                "Referer":    headers.get("Referer", headers.get("referer", "")),
            }
        },
        "response": {
            "http_code": http_code,
            "body":      body,
        },
        "messages": messages,
    }

# ── Tail file ───────────────────────────────────────────────────────────────
def tail_f(filepath):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # seek ke end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

# ── Main ────────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  OJS WAF Real-Time Inference")
    print("=" * 55)
    print(f"[*] Log path  : {LOG_PATH}")
    print(f"[*] Model path: {MODEL_PATH}")
    print()

    # Tunggu log file ada
    while not os.path.exists(LOG_PATH):
        print(f"[*] Waiting for log file: {LOG_PATH}")
        time.sleep(2)

    # Load model
    try:
        model = load_model(MODEL_PATH)
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}")
        raise

    print(f"[*] Watching audit log for new entries...\n")

    for line in tail_f(LOG_PATH):
        if not line:
            continue
        try:
            raw_entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        try:
            input_data = extract_input(raw_entry)

            # Predict using predict_from_json
            result = model.predict_from_json(input_data)

            prediction  = result["prediction"]
            probability = result["probability"]
            decision    = result["decision"]
            threshold   = result["threshold"]

            confidence = f"{probability*100:.1f}%" if probability is not None else "N/A"

            # Info tambahan untuk context
            method  = input_data["request"]["method"]
            uri     = input_data["request"]["uri"]
            status  = input_data["response"]["http_code"]
            ip      = input_data["client_ip"]
            ts      = input_data["time_stamp"]

            # Print result
            flag = "[ATTACK]" if decision == "ATTACK" else "NORMAL"
            print(f"{flag} | {ts} | {ip} | {method} {uri} | HTTP {status} | prob={confidence}")

        except Exception as e:
            print(f"[ERROR] Failed to process entry: {e}")
            continue

if __name__ == "__main__":
    main()
