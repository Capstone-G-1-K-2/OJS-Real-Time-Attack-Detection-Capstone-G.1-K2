#!/usr/bin/env python3
"""Export live ModSecurity events into a training-compatible CSV."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


DEFAULT_OUTPUT_PATH = Path("data/processed/retraining_dataset.csv")

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


def build_select_sql(include_sort_id: bool = False) -> str:
    sort_column = "id AS __sort_id," if include_sort_id else ""

    return f"""
        SELECT
            {sort_column}
            DATE_FORMAT(timestamp, '%%a %%b %%e %%H:%%i:%%s %%Y') AS timestamp,
            COALESCE(source_ip, '0.0.0.0') AS source_ip,
            COALESCE(method, 'GET') AS method,
            COALESCE(uri, '/') AS uri,
            COALESCE(status, 0) AS status,
            COALESCE(bytes_sent, 0) AS bytes_sent,
            COALESCE(request_time, 0.0) AS request_time,
            COALESCE(user_agent, '') AS user_agent,
            COALESCE(user_agent_len, 0) AS user_agent_len,
            COALESCE(uri_len, 0) AS uri_len,
            COALESCE(severity, 'INFO') AS severity,
            COALESCE(severity_score, 0) AS severity_score,
            COALESCE(rule_id, '') AS rule_id,
            COALESCE(matched_data, '') AS matched_data,
            COALESCE(msg, '') AS msg,
            COALESCE(is_blocked, 0) AS is_blocked,
            COALESCE(rule_count, 0) AS rule_count,
            COALESCE(has_sqli, 0) AS has_sqli,
            COALESCE(has_xss, 0) AS has_xss,
            COALESCE(has_suspicious_path, 0) AS has_suspicious_path,
            COALESCE(has_path_traversal, 0) AS has_path_traversal,
            COALESCE(has_command_injection, 0) AS has_command_injection,
            COALESCE(has_cve_2022_24181, 0) AS has_cve_2022_24181,
            COALESCE(missing_csrf_token, 0) AS missing_csrf_token,
            COALESCE(has_suspicious_referer, 0) AS has_suspicious_referer,
            COALESCE(has_cve_2024_xss_privesc, 0) AS has_cve_2024_xss_privesc,
            COALESCE(has_privesc_attempt, 0) AS has_privesc_attempt,
            COALESCE(has_cve_2021_32626, 0) AS has_cve_2021_32626,
            CASE
                WHEN human_label IS NOT NULL THEN human_label
                WHEN COALESCE(rule_count, 0) > 0 THEN 1
                ELSE 0
            END AS label
        FROM modsec_events
    """


def build_query(
    *,
    first: int | None = None,
    last: int | None = None,
    start_row: int | None = None,
    end_row: int | None = None,
) -> tuple[str, tuple[int, ...]]:
    select_sql = build_select_sql()

    if last is not None:
        select_with_sort_id = build_select_sql(include_sort_id=True)
        query = f"""
            SELECT *
            FROM (
                {select_with_sort_id}
                ORDER BY id DESC
                LIMIT %s
            ) AS latest_events
            ORDER BY __sort_id
        """
        return query, (last,)

    if start_row is not None and end_row is not None:
        limit = end_row - start_row + 1
        offset = start_row - 1
        query = f"""
            {select_sql}
            ORDER BY id
            LIMIT %s OFFSET %s
        """
        return query, (limit, offset)

    query = f"""
        {select_sql}
        ORDER BY id
    """

    if first is not None:
        query += "\n        LIMIT %s"
        return query, (first,)

    return query, ()


def export_events(
    output_path: Path,
    first: int | None = None,
    last: int | None = None,
    start_row: int | None = None,
    end_row: int | None = None,
) -> int:
    load_dotenv()

    from src.auth.db import get_connection

    conn = get_connection()

    try:
        with conn.cursor() as cur:
            query, params = build_query(
                first=first,
                last=last,
                start_row=start_row,
                end_row=end_row,
            )
            cur.execute(query, params)
            rows = cur.fetchall()

    finally:
        conn.close()

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=CSV_COLUMNS,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export modsec_events into a retraining CSV. "
            "The label uses human_label first, otherwise falls back to rule_count > 0."
        )
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help=f"Output CSV path. Default: {DEFAULT_OUTPUT_PATH}",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Alias for --first. Kept for compatibility.",
    )
    parser.add_argument(
        "--first",
        type=int,
        default=None,
        help="Export the first N rows ordered by modsec_events.id.",
    )
    parser.add_argument(
        "--last",
        type=int,
        default=None,
        help="Export the last N rows ordered by modsec_events.id.",
    )
    parser.add_argument(
        "--start-row",
        type=int,
        default=None,
        help="Start row number for an inclusive row range ordered by modsec_events.id. Starts at 1.",
    )
    parser.add_argument(
        "--end-row",
        type=int,
        default=None,
        help="End row number for an inclusive row range ordered by modsec_events.id.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    first = args.first if args.first is not None else args.limit
    modes = [
        first is not None,
        args.last is not None,
        args.start_row is not None or args.end_row is not None,
    ]

    if sum(modes) > 1:
        raise SystemExit(
            "Choose only one export mode: --first/--limit, --last, or --start-row with --end-row."
        )

    if args.start_row is not None or args.end_row is not None:
        if args.start_row is None or args.end_row is None:
            raise SystemExit("--start-row and --end-row must be used together.")
        if args.start_row < 1:
            raise SystemExit("--start-row must be >= 1.")
        if args.end_row < args.start_row:
            raise SystemExit("--end-row must be >= --start-row.")

    for name, value in (
        ("--first", first),
        ("--last", args.last),
    ):
        if value is not None and value < 1:
            raise SystemExit(f"{name} must be >= 1.")

    count = export_events(
        output_path=Path(args.output),
        first=first,
        last=args.last,
        start_row=args.start_row,
        end_row=args.end_row,
    )

    print(
        f"Exported {count} rows to {args.output}"
    )


if __name__ == "__main__":
    main()
