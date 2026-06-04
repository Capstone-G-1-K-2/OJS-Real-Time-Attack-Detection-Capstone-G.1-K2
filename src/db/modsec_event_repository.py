from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from src.auth.db import get_connection


TEXT_FIELDS = {
    "source_ip",
    "method",
    "uri",
    "user_agent",
    "severity",
    "rule_id",
    "matched_data",
    "msg",
}

INT_FIELDS = {
    "status",
    "bytes_sent",
    "user_agent_len",
    "uri_len",
    "severity_score",
    "rule_count",
    "has_sqli",
    "has_xss",
    "has_suspicious_path",
    "has_path_traversal",
    "has_command_injection",
    "has_cve_2022_24181",
    "missing_csrf_token",
    "has_suspicious_referer",
    "has_cve_2024_xss_privesc",
    "has_privesc_attempt",
    "has_cve_2021_32626",
}


def _parse_timestamp(value: Any):
    if not value:
        return None

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    value = str(value).strip()

    for fmt in (
        "%a %b %d %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    return None


def _text_or_none(value: Any):
    if value is None:
        return None

    value = str(value)
    return value if value else None


def _int_or_zero(value: Any) -> int:
    if value is None or value == "":
        return 0

    if isinstance(value, bool):
        return int(value)

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float_or_zero(value: Any) -> float:
    if value is None or value == "":
        return 0.0

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _probability_or_none(value: Any):
    if value is None or value == "":
        return None

    try:
        probability = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None

    return probability.quantize(Decimal("0.00001"))


def _prediction_or_none(value: Any):
    if value is None or value == "":
        return None

    try:
        return 1 if int(value) == 1 else 0
    except (TypeError, ValueError):
        return 1 if bool(value) else 0


def insert_modsec_event(
    parsed_row: dict,
    model_prediction=None,
    model_probability=None,
    attack_event_id=None,
) -> int:
    columns = [
        "attack_event_id",
        "timestamp",
        "source_ip",
        "method",
        "uri",
        "status",
        "bytes_sent",
        "request_time",
        "user_agent",
        "user_agent_len",
        "uri_len",
        "severity",
        "severity_score",
        "rule_id",
        "matched_data",
        "msg",
        "is_blocked",
        "rule_count",
        "has_sqli",
        "has_xss",
        "has_suspicious_path",
        "has_path_traversal",
        "has_command_injection",
        "has_cve_2022_24181",
        "missing_csrf_token",
        "has_suspicious_referer",
        "has_cve_2024_xss_privesc",
        "has_privesc_attempt",
        "has_cve_2021_32626",
        "model_prediction",
        "model_probability",
    ]

    values = {
        "attack_event_id": attack_event_id,
        "timestamp": _parse_timestamp(parsed_row.get("timestamp")),
        "request_time": _float_or_zero(parsed_row.get("request_time")),
        "is_blocked": _int_or_zero(parsed_row.get("is_blocked")),
        "model_prediction": _prediction_or_none(model_prediction),
        "model_probability": _probability_or_none(model_probability),
    }

    for field in TEXT_FIELDS:
        values[field] = _text_or_none(parsed_row.get(field))

    for field in INT_FIELDS:
        values[field] = _int_or_zero(parsed_row.get(field))

    placeholders = ", ".join(["%s"] * len(columns))
    column_sql = ", ".join(columns)

    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO modsec_events (
                    {column_sql}
                )
                VALUES ({placeholders})
                """,
                tuple(values[column] for column in columns),
            )

            modsec_event_id = cur.lastrowid

        conn.commit()
        return modsec_event_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def link_attack_event(
    modsec_event_id: int,
    attack_event_id: int,
) -> None:
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE modsec_events
                SET attack_event_id = %s
                WHERE id = %s
                """,
                (
                    attack_event_id,
                    modsec_event_id,
                ),
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def mark_false_positive_by_attack_event_id(
    attack_event_id: int,
) -> None:
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE modsec_events
                SET
                    human_label = 0,
                    label_source = 'telegram',
                    labeled_at = NOW()
                WHERE attack_event_id = %s
                """,
                (attack_event_id,),
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()
