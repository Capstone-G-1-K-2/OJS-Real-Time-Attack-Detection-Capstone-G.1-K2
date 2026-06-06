"""Script untuk mengukur kecepatan inferensi murni (tanpa Telegram/DB latency)"""
import os
import sys
import json
import time
import argparse
from pathlib import Path

# Setup path agar bisa import module inference
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
INFERENCE_DIR = PROJECT_ROOT / "docker-ojs" / "inference"
sys.path.insert(0, str(INFERENCE_DIR))

# Import module model wrapper (sama persis dengan yang ada di main.py)
import pickle
from src.inference.model_wrapper import ModelWrapper

def load_model(path):
    print(f"[*] Loading model from {path}...")
    with open(path, "rb") as f:
        model = pickle.load(f)
    if not hasattr(model, "predict_from_json"):
        model = ModelWrapper.from_pipeline(model)
    return model

def extract_client_ip(headers: dict, transaction: dict) -> str:
    forwarded_for = headers.get("X-Forwarded-For", "")
    forwarded_ip = forwarded_for.split(",")[0].strip() if forwarded_for else ""
    return (
        headers.get("X-Real-IP")
        or headers.get("x-real-ip")
        or forwarded_ip
        or transaction.get("client_ip")
        or "0.0.0.0"
    )

def extract_input(entry: dict) -> dict:
    t = entry.get("transaction", entry)
    request = t.get("request", {})
    response = t.get("response", {})
    headers = request.get("headers", {})
    client_ip = extract_client_ip(headers, t)
    return {
        "time_stamp": t.get("time_stamp", "2024-01-01T00:00:00Z"),
        "client_ip": client_ip,
        "request": {
            "method": request.get("method", "GET"),
            "uri": request.get("uri", "/"),
            "headers": {
                "User-Agent": headers.get("User-Agent", headers.get("user-agent", "")),
                "Host": headers.get("Host", headers.get("host", "")),
                "Referer": headers.get("Referer", headers.get("referer", "")),
            },
        },
        "response": {
            "http_code": response.get("http_code", 0),
            "body": response.get("body", ""),
        },
        "messages": t.get("messages", []),
    }

def main():
    parser = argparse.ArgumentParser(description="Benchmark Pure Inference Speed")
    parser.add_argument('--model', type=str, default=str(PROJECT_ROOT / "models" / "trained_models" / "modsec_xgb.pkl"))
    parser.add_argument('--files', nargs='+', required=True, help='List of log files to benchmark')
    args = parser.parse_args()

    model = load_model(args.model)

    print("\n" + "=" * 80)
    print("  PURE INFERENCE BENCHMARK RESULTS (Tanpa DB & Telegram Latency)")
    print("=" * 80)

    for filepath in args.files:
        if not os.path.exists(filepath):
            print(f"[WARNING] File not found: {filepath}")
            continue

        file_size_kb = os.path.getsize(filepath) / 1024
        
        # Load logs ke memory dulu agar kita tidak menghitung kecepatan baca SSD/HDD 
        # murni menghitung kecepatan Model memproses string -> feature -> prediction
        logs_in_memory = []
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_entry = json.loads(line)
                    logs_in_memory.append(raw_entry)
                except json.JSONDecodeError:
                    continue
        
        tx_count = len(logs_in_memory)
        if tx_count == 0:
            print(f"- [WARNING] Skipping {filepath} (0 valid JSON logs found)")
            continue

        # ==== MULAI PENGUKURAN WAKTU ====
        start_time = time.perf_counter()
        
        for raw_entry in logs_in_memory:
            # 1. Parsing format input
            input_data = extract_input(raw_entry)
            # 2. Prediksi model
            result = model.predict_from_json(input_data)
        
        end_time = time.perf_counter()
        # ==== SELESAI PENGUKURAN ====
        
        elapsed_ms = (end_time - start_time) * 1000
        
        print(f"- {tx_count} transactions ({file_size_kb:.1f} KB) took: {elapsed_ms:.2f} ms")

    print("=" * 80)

if __name__ == "__main__":
    main()
