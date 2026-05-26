#!/usr/bin/env python3

from __future__ import annotations

import csv
from pathlib import Path

from dotenv import load_dotenv

from src.auth.db import get_connection


OUTPUT_PATH = Path("data/processed/retraining_dataset.csv")

CSV_COLUMNS = [
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
    "label",
]


def export_labeled_events() -> int:
    load_dotenv()

    selected_columns = ", ".join(
        CSV_COLUMNS[:-1]
    )

    conn = get_connection()

    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    {selected_columns},
                    human_label AS label
                FROM modsec_events
                WHERE human_label IS NOT NULL
                ORDER BY id
                """
            )

            rows = cur.fetchall()

    finally:
        conn.close()

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=CSV_COLUMNS,
        )
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


if __name__ == "__main__":
    count = export_labeled_events()
    print(
        f"Exported {count} labeled rows to {OUTPUT_PATH}"
    )
