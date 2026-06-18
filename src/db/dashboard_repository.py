from __future__ import annotations

from datetime import datetime
from time import monotonic
from typing import Any

import psutil

from src.auth.db import get_connection

TABLE_COLUMNS_CACHE_SECONDS = 10
TABLE_COLUMNS_CACHE: dict[str, tuple[float, set[str]]] = {}


def _empty_dashboard() -> dict[str, Any]:
    return {
        "counts": {
            "attacks_1_day": 0,
            "attacks_7_days": 0,
            "attacks_30_days": 0,
        },
        "live_attacks": [],
        "attack_types": [
            {"attack_type": "XSS", "total": 0},
            {"attack_type": "RCE", "total": 0},
        ],
        "top_countries": [],
        "system": _get_system_metrics(),
    }


def _get_table_columns(cur, table_name: str) -> set[str]:
    cached = TABLE_COLUMNS_CACHE.get(table_name)
    now = monotonic()

    if cached and now - cached[0] <= TABLE_COLUMNS_CACHE_SECONDS:
        return set(cached[1])

    cur.execute(
        """
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = %s
        """,
        (table_name,),
    )

    columns = {
        row["COLUMN_NAME"]
        for row in cur.fetchall()
    }

    TABLE_COLUMNS_CACHE[table_name] = (now, columns)

    return set(columns)


def _format_datetime(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    return value


def _as_float(value):
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _get_system_metrics() -> dict[str, float]:
    return {
        "cpu_percent": float(psutil.cpu_percent(interval=0.2)),
        "ram_percent": float(psutil.virtual_memory().percent),
    }


def _fetch_counts(cur) -> dict[str, int]:
    cur.execute(
        """
        SELECT
            COALESCE(
                SUM(CASE WHEN detected_at >= NOW() - INTERVAL 1 DAY THEN 1 ELSE 0 END),
                0
            ) AS attacks_1_day,
            COALESCE(
                SUM(CASE WHEN detected_at >= NOW() - INTERVAL 7 DAY THEN 1 ELSE 0 END),
                0
            ) AS attacks_7_days,
            COALESCE(
                SUM(CASE WHEN detected_at >= NOW() - INTERVAL 30 DAY THEN 1 ELSE 0 END),
                0
            ) AS attacks_30_days
        FROM attack_events
        """
    )
    row = cur.fetchone() or {}

    return {
        "attacks_1_day": int(row.get("attacks_1_day") or 0),
        "attacks_7_days": int(row.get("attacks_7_days") or 0),
        "attacks_30_days": int(row.get("attacks_30_days") or 0),
    }


def _fetch_live_attacks(
    cur,
    attack_columns: set[str],
    modsec_columns: set[str],
    *,
    after_id: int | None = None,
    limit: int = 20,
    ascending: bool = False,
) -> list[dict[str, Any]]:
    country_expr = (
        "COALESCE(NULLIF(a.attacker_country, ''), 'Unknown')"
        if "attacker_country" in attack_columns
        else "'Unknown'"
    )

    attack_ms_expr = "NULL"

    if "attack_ms" in attack_columns:
        attack_ms_expr = "a.attack_ms"
    elif (
        "attack_event_id" in modsec_columns
        and "request_time" in modsec_columns
    ):
        attack_ms_expr = """
            (
                SELECT m.request_time * 1000
                FROM modsec_events m
                WHERE m.attack_event_id = a.id
                LIMIT 1
            )
        """

    probability_expr = (
        "a.probability"
        if "probability" in attack_columns
        else "NULL"
    )
    attack_url_expr = (
        "COALESCE(a.attack_url, '')"
        if "attack_url" in attack_columns
        else "''"
    )
    attacker_ip_expr = (
        "COALESCE(a.attacker_ip, '')"
        if "attacker_ip" in attack_columns
        else "''"
    )

    where_clause = ""
    params: list[Any] = []

    if after_id is not None:
        where_clause = "WHERE a.id > %s"
        params.append(after_id)

    order_direction = "ASC" if ascending else "DESC"
    params.append(limit)

    cur.execute(
        f"""
        SELECT
            a.id,
            a.detected_at,
            {attacker_ip_expr} AS attacker_ip,
            {country_expr} AS attacker_country,
            COALESCE(a.attack_type, 'Unknown') AS attack_type,
            {attack_ms_expr} AS attack_ms,
            {probability_expr} AS probability,
            {attack_url_expr} AS attack_url
        FROM attack_events a
        {where_clause}
        ORDER BY a.id {order_direction}
        LIMIT %s
        """,
        tuple(params),
    )

    attacks = []

    for row in cur.fetchall():
        attacks.append(
            {
                "id": int(row.get("id") or 0),
                "detected_at": _format_datetime(row.get("detected_at")),
                "attacker_ip": row.get("attacker_ip") or "-",
                "attacker_country": row.get("attacker_country") or "Unknown",
                "attack_type": row.get("attack_type") or "Unknown",
                "attack_ms": _as_float(row.get("attack_ms")),
                "probability": _as_float(row.get("probability")),
                "attack_url": row.get("attack_url") or "",
            }
        )

    return attacks


def _fetch_latest_attack_id(cur) -> int | None:
    cur.execute(
        """
        SELECT MAX(id) AS latest_id
        FROM attack_events
        """
    )
    row = cur.fetchone() or {}
    latest_id = row.get("latest_id")

    return int(latest_id) if latest_id is not None else None


def _fetch_attack_types(cur) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT attack_type, COUNT(*) AS total
        FROM (
            SELECT
                CASE
                    WHEN UPPER(COALESCE(attack_type, '')) LIKE '%XSS%' THEN 'XSS'
                    WHEN UPPER(COALESCE(attack_type, '')) LIKE '%RCE%' THEN 'RCE'
                    WHEN UPPER(COALESCE(attack_type, '')) LIKE '%UPLOAD%' THEN 'RCE'
                    WHEN UPPER(COALESCE(attack_type, '')) LIKE '%COMMAND%' THEN 'RCE'
                    ELSE NULL
                END AS attack_type
            FROM attack_events
            WHERE detected_at >= NOW() - INTERVAL 30 DAY
        ) AS normalized_attacks
        WHERE attack_type IN ('XSS', 'RCE')
        GROUP BY attack_type
        ORDER BY attack_type ASC
        """
    )

    totals = {
        "XSS": 0,
        "RCE": 0,
    }

    for row in cur.fetchall():
        totals[row["attack_type"]] = int(row.get("total") or 0)

    return [
        {"attack_type": "XSS", "total": totals["XSS"]},
        {"attack_type": "RCE", "total": totals["RCE"]},
    ]


def _fetch_top_countries(
    cur,
    attack_columns: set[str],
) -> list[dict[str, Any]]:
    if "attacker_country" not in attack_columns:
        cur.execute(
            """
            SELECT COUNT(*) AS total
            FROM attack_events
            WHERE detected_at >= NOW() - INTERVAL 30 DAY
            """
        )
        row = cur.fetchone() or {}
        total = int(row.get("total") or 0)

        return [
            {
                "country": "Unknown",
                "total": total,
            }
        ] if total else []

    cur.execute(
        """
        SELECT
            COALESCE(NULLIF(attacker_country, ''), 'Unknown') AS country,
            COUNT(*) AS total
        FROM attack_events
        WHERE detected_at >= NOW() - INTERVAL 30 DAY
        GROUP BY COALESCE(NULLIF(attacker_country, ''), 'Unknown')
        ORDER BY total DESC, country ASC
        LIMIT 5
        """
    )

    return [
        {
            "country": row.get("country") or "Unknown",
            "total": int(row.get("total") or 0),
        }
        for row in cur.fetchall()
    ]


def get_dashboard_data() -> dict[str, Any]:
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            attack_columns = _get_table_columns(
                cur,
                "attack_events",
            )

            if not attack_columns:
                return _empty_dashboard()

            modsec_columns = _get_table_columns(
                cur,
                "modsec_events",
            )

            return {
                "counts": _fetch_counts(cur),
                "live_attacks": _fetch_live_attacks(
                    cur,
                    attack_columns,
                    modsec_columns,
                ),
                "attack_types": _fetch_attack_types(cur),
                "top_countries": _fetch_top_countries(
                    cur,
                    attack_columns,
                ),
                "system": _get_system_metrics(),
            }

    finally:
        conn.close()


def get_latest_attack_id() -> int | None:
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            attack_columns = _get_table_columns(
                cur,
                "attack_events",
            )

            if not attack_columns:
                return None

            return _fetch_latest_attack_id(cur)

    finally:
        conn.close()


def get_attack_events_after(
    attack_id: int,
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    conn = get_connection()

    try:
        with conn.cursor() as cur:
            attack_columns = _get_table_columns(
                cur,
                "attack_events",
            )

            if not attack_columns:
                return []

            modsec_columns = _get_table_columns(
                cur,
                "modsec_events",
            )

            return _fetch_live_attacks(
                cur,
                attack_columns,
                modsec_columns,
                after_id=attack_id,
                limit=limit,
                ascending=True,
            )

    finally:
        conn.close()
