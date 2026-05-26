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

from src.db.attack_repository import (
    insert_attack_event,
)

from src.db.modsec_event_repository import (
    insert_modsec_event,
    link_attack_event,
)

from src.preprocessing.modsec_json_parser import (
    _extract_from_json_transaction,
)

from src.security.attack_classifier import (
    extract_attack_type,
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


def extract_client_ip(
    headers: dict,
    transaction: dict,
) -> str:

    forwarded_for = headers.get(
        "X-Forwarded-For",
        "",
    )

    forwarded_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else ""
    )

    return (
        headers.get("X-Real-IP")
        or headers.get("x-real-ip")
        or forwarded_ip
        or transaction.get("client_ip")
        or "0.0.0.0"
    )


def extract_input(entry: dict) -> dict:

    t = entry.get(
        "transaction",
        entry,
    )

    request = t.get(
        "request",
        {},
    )

    response = t.get(
        "response",
        {},
    )

    headers = request.get(
        "headers",
        {},
    )

    client_ip = extract_client_ip(
        headers,
        t,
    )

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


def process_prediction_result(
    result: dict,
):

    prediction = result.get(
        "prediction"
    )

    probability = result.get(
        "probability"
    )

    decision = result.get(
        "decision"
    )

    threshold = result.get(
        "threshold"
    )

    confidence = (
        f"{probability * 100:.1f}%"
        if probability is not None
        else "N/A"
    )

    return (
        prediction,
        probability,
        decision,
        threshold,
        confidence,
    )


def parse_mysql_timestamp(value):

    if not value:
        return None

    for fmt in (
        "%a %b %d %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ):

        try:

            return datetime.strptime(
                value,
                fmt,
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        except ValueError:
            continue

    return None


def print_detection_log(
    flag,
    ts,
    ip,
    method,
    uri,
    status,
    confidence,
):

    print(
        f"{flag} | "
        f"{ts} | "
        f"{ip} | "
        f"{method} {uri} | "
        f"HTTP {status} | "
        f"prob={confidence}"
    )


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

    model = load_model(
        MODEL_PATH
    )

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

            raw_entry = json.loads(
                line
            )

        except json.JSONDecodeError:
            continue

        try:

            input_data = extract_input(
                raw_entry
            )

            parsed_row = (
                _extract_from_json_transaction(
                    input_data
                )
            )

            result = (
                model.predict_from_json(
                    input_data
                )
            )

            (
                prediction,
                probability,
                decision,
                threshold,
                confidence,
            ) = process_prediction_result(
                result
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

            sql_timestamp = (
                parse_mysql_timestamp(
                    ts
                )
            )

            messages = input_data[
                "messages"
            ]

            flag = (
                "[ATTACK]"
                if decision == "ATTACK"
                else "NORMAL"
            )

            modsec_event_id = None
            event_id = None

            try:

                modsec_event_id = (
                    insert_modsec_event(
                        parsed_row=parsed_row,
                        model_prediction=prediction,
                        model_probability=probability,
                    )
                )

            except Exception as db_error:

                print(
                    "[WARNING] Failed to store modsec event:",
                    db_error,
                )

            if decision == "ATTACK":

                attack_type = (
                    extract_attack_type(
                        messages
                    )
                )

                try:

                    event_id = (
                        insert_attack_event(
                            detected_at=sql_timestamp,
                            attack_type=attack_type,
                            probability=probability,
                            attack_url=uri,
                            attacker_ip=ip,
                        )
                    )

                    print(
                        f"[*] Attack event stored | id={event_id}"
                    )

                except Exception as db_error:

                    print(
                        "[WARNING] Failed to store attack event:",
                        db_error,
                    )

                if event_id is None:

                    print(
                        "[WARNING] Skipping Telegram alert because attack event was not stored"
                    )

                    print_detection_log(
                        flag=flag,
                        ts=ts,
                        ip=ip,
                        method=method,
                        uri=uri,
                        status=status,
                        confidence=confidence,
                    )

                    continue

                if modsec_event_id is not None:

                    try:

                        link_attack_event(
                            modsec_event_id,
                            event_id,
                        )

                    except Exception as db_error:

                        print(
                            "[WARNING] Failed to link modsec event:",
                            db_error,
                        )

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

                    try:

                        asyncio.run(
                            notifier.send_alert(
                                telegram_message,
                                event_id,
                                probability,
                            )
                        )

                    except Exception as notify_error:

                        print(
                            "[WARNING] Telegram notification failed:",
                            notify_error,
                        )

                    last_alert_time = now

            print_detection_log(
                flag=flag,
                ts=ts,
                ip=ip,
                method=method,
                uri=uri,
                status=status,
                confidence=confidence,
            )

        except Exception as e:

            print(
                f"[ERROR] Failed to process entry: {e}"
            )


if __name__ == "__main__":
    main()
