#!/usr/bin/env python3

import os
import json
import time
import pickle
import asyncio

from datetime import datetime

from src.alerts.telegram_notifier import (
    TelegramNotifier,
)

from src.alerts.alert_formatter import (
    build_attack_alert,
)

LOG_PATH = "/var/log/modsecurity/audit.log"

MODEL_PATH = "/app/model.pkl"

ALERT_COOLDOWN_SECONDS = 10


def load_model(path):
    print(f"[*] Loading model from {path}...")

    with open(path, "rb") as f:
        model = pickle.load(f)

    print(f"[*] Model loaded: {type(model)}")

    return model


def extract_input(entry: dict) -> dict:
    t = entry.get("transaction", entry)

    request = t.get("request", {})
    headers = request.get("headers", {})
    client_ip = (
        headers.get("X-Real-IP")
        or headers.get("x-real-ip")
        or headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or t.get("client_ip")
        or "0.0.0.0"
    )
    response = t.get("response", {})

    return {
        "time_stamp": t.get(
            "time_stamp",
            datetime.utcnow().isoformat() + "Z",
        ),

        "client_ip": client_ip,

        "request": {
            "method": request.get(
                "method",
                "GET",
            ),

            "uri": request.get(
                "uri",
                "/",
            ),

            "headers": {
                "User-Agent": headers.get(
                    "User-Agent",
                    headers.get("user-agent", ""),
                ),

                "Host": headers.get(
                    "Host",
                    headers.get("host", ""),
                ),

                "Referer": headers.get(
                    "Referer",
                    headers.get("referer", ""),
                ),
            },
        },

        "response": {
            "http_code": response.get(
                "http_code",
                0,
            ),

            "body": response.get(
                "body",
                "",
            ),
        },

        "messages": t.get(
            "messages",
            [],
        ),
    }


def tail_f(filepath):
    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as f:

        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            yield line.strip()


def main():
    print("=" * 55)
    print("  OJS WAF Real-Time Inference")
    print("=" * 55)

    print(f"[*] Log path  : {LOG_PATH}")
    print(f"[*] Model path: {MODEL_PATH}")
    print()

    while not os.path.exists(LOG_PATH):
        print(
            f"[*] Waiting for log file: {LOG_PATH}"
        )

        time.sleep(2)

    model = load_model(MODEL_PATH)

    notifier = TelegramNotifier()

    print(
        "[*] Telegram notifier initialized"
    )

    print(
        "[*] Watching audit log for new entries...\n"
    )

    last_alert_time = 0

    for line in tail_f(LOG_PATH):

        if not line:
            continue

        try:
            raw_entry = json.loads(line)

        except json.JSONDecodeError:
            continue

        try:
            input_data = extract_input(raw_entry)

            result = model.predict_from_json(
                input_data
            )

            prediction = result["prediction"]

            probability = result["probability"]

            decision = result["decision"]

            threshold = result["threshold"]

            confidence = (
                f"{probability * 100:.1f}%"
                if probability is not None
                else "N/A"
            )

            method = input_data[
                "request"
            ]["method"]

            uri = input_data[
                "request"
            ]["uri"]

            status = input_data[
                "response"
            ]["http_code"]

            ip = input_data[
                "client_ip"
            ]

            ts = input_data[
                "time_stamp"
            ]

            flag = (
                "[ATTACK]"
                if decision == "ATTACK"
                else "NORMAL"
            )

            if decision == "ATTACK":

                now = time.time()

                if (
                    now - last_alert_time
                    >= ALERT_COOLDOWN_SECONDS
                ):

                    telegram_message = (
                        build_attack_alert(
                            timestamp=ts,
                            source_ip=ip,
                            method=method,
                            uri=uri,
                            http_status=status,
                            prediction=prediction,
                            confidence=confidence,
                            threshold=threshold,
                        )
                    )

                    asyncio.run(
                        notifier.send_alert_with_retry(
                            telegram_message
                        )
                    )

                    last_alert_time = now

            print(
                f"{flag} | "
                f"{ts} | "
                f"{ip} | "
                f"{method} {uri} | "
                f"HTTP {status} | "
                f"prob={confidence}"
            )

        except Exception as e:
            print(
                f"[ERROR] Failed to process entry: {e}"
            )


if __name__ == "__main__":
    main()
