from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

from src.preprocessing.pattern_rules import (
    SQLI_PATTERNS,
    SUSPICIOUS_PATH_PATTERNS,
    XSS_PATTERNS,
)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _severity_to_score(severity: str | None) -> int:
    if not severity:
        return 0

    mapping = {
        "EMERGENCY": 5,
        "ALERT": 5,
        "CRITICAL": 4,
        "ERROR": 3,
        "WARNING": 2,
        "NOTICE": 1,
        "INFO": 0,
        "DEBUG": 0,
    }
    return mapping.get(str(severity).upper(), 0)


def _contains_pattern(text: str, patterns: list[str]) -> int:
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return 1
    return 0


def _extract_request(payload: dict[str, Any]) -> tuple[str, str, str]:
    tx = payload.get("transaction", {})
    request = tx.get("request", {})

    method = str(request.get("method") or "GET")
    uri = str(request.get("uri") or request.get("path") or "/")
    user_agent = str(request.get("headers", {}).get("User-Agent") or "")
    return method, uri, user_agent


def _extract_messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    tx = payload.get("transaction", {})
    messages = tx.get("messages")
    if isinstance(messages, list):
        return messages
    return []


def parse_modsecurity_jsonl(file_path: str | Path) -> pd.DataFrame:
    """Parse ModSecurity JSONL audit log into feature dataframe.

    Expected format: one JSON object per line.
    The output can be used for model training when labels exist, or inference when labels are absent.
    """
    path = Path(file_path)
    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            method, uri, user_agent = _extract_request(payload)
            messages = _extract_messages(payload)

            full_text = f"{uri} {' '.join(str(m.get('message', '')) for m in messages)}"
            severity_score = max(
                (_severity_to_score(str(m.get("details", {}).get("severity") or "")) for m in messages),
                default=0,
            )

            row = {
                "source_file": path.name,
                "line_number": line_number,
                "method": method,
                "uri": uri,
                "status": _safe_int(payload.get("transaction", {}).get("response", {}).get("http_code"), 200),
                "bytes_sent": _safe_int(payload.get("transaction", {}).get("response", {}).get("body_bytes_sent"), 0),
                "request_time": _safe_float(payload.get("transaction", {}).get("time"), 0.0),
                "rule_count": len(messages),
                "severity_score": severity_score,
                "user_agent_len": len(user_agent),
                "uri_len": len(uri),
                "has_sqli_pattern": _contains_pattern(full_text, SQLI_PATTERNS),
                "has_xss_pattern": _contains_pattern(full_text, XSS_PATTERNS),
                "has_suspicious_path": _contains_pattern(uri, SUSPICIOUS_PATH_PATTERNS),
            }

            # If explicit label exists in raw log, keep it for supervised training.
            label = payload.get("label")
            if label is not None:
                row["label"] = int(label)
            elif severity_score >= 3 or row["has_sqli_pattern"] or row["has_xss_pattern"] or row["has_suspicious_path"]:
                row["label"] = 1
            else:
                row["label"] = 0

            rows.append(row)

    return pd.DataFrame(rows)


def parse_modsecurity_audit_log(file_path: str | Path) -> pd.DataFrame:
    """Parse native ModSecurity audit log format (--id-A-- .. --id-Z--)."""
    path = Path(file_path)
    rows: list[dict[str, Any]] = []

    current_section = ""
    current_entry: dict[str, Any] = {}

    def flush_entry(entry: dict[str, Any]) -> None:
        if not entry:
            return

        method = str(entry.get("method") or "GET")
        uri = str(entry.get("uri") or "/")
        user_agent = str(entry.get("user_agent") or "")
        messages = entry.get("messages") or []
        full_text = f"{uri} {' '.join(messages)}"
        severity_score = max((int(s) for s in entry.get("severity_scores", [])), default=0)

        row = {
            "source_file": path.name,
            "method": method,
            "uri": uri,
            "status": _safe_int(entry.get("status"), 200),
            "bytes_sent": _safe_int(entry.get("bytes_sent"), 0),
            "request_time": _safe_float(entry.get("request_time"), 0.0),
            "rule_count": int(entry.get("rule_count") or len(messages)),
            "severity_score": severity_score,
            "user_agent_len": len(user_agent),
            "uri_len": len(uri),
            "has_sqli_pattern": _contains_pattern(full_text, SQLI_PATTERNS),
            "has_xss_pattern": _contains_pattern(full_text, XSS_PATTERNS),
            "has_suspicious_path": _contains_pattern(uri, SUSPICIOUS_PATH_PATTERNS),
            "label": 0,
        }
        if severity_score >= 3 or row["has_sqli_pattern"] or row["has_xss_pattern"] or row["has_suspicious_path"]:
            row["label"] = 1
        rows.append(row)

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")

            marker = re.match(r"^--[a-zA-Z0-9]+-([A-Z])--$", line)
            if marker:
                section = marker.group(1)
                current_section = section
                if section == "A":
                    current_entry = {
                        "messages": [],
                        "severity_scores": [],
                        "rule_count": 0,
                    }
                elif section == "Z":
                    flush_entry(current_entry)
                    current_entry = {}
                continue

            if not current_entry:
                continue

            if current_section == "B":
                # Request line: METHOD /path HTTP/1.1
                if "method" not in current_entry:
                    req = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", line)
                    if req:
                        current_entry["method"] = req.group(1)
                        current_entry["uri"] = req.group(2)
                if line.lower().startswith("user-agent:"):
                    current_entry["user_agent"] = line.split(":", 1)[1].strip()

            elif current_section == "F":
                # Response line: HTTP/1.1 404 Not Found
                if "status" not in current_entry:
                    status_match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", line)
                    if status_match:
                        current_entry["status"] = _safe_int(status_match.group(1), 200)
                if line.lower().startswith("content-length:"):
                    current_entry["bytes_sent"] = _safe_int(line.split(":", 1)[1].strip(), 0)

            elif current_section == "H":
                if line.startswith("Message:"):
                    current_entry["messages"].append(line)
                    current_entry["rule_count"] = int(current_entry.get("rule_count", 0)) + 1

                    sev_match = re.search(r"\[severity\s+\"([^\"]+)\"\]", line, flags=re.IGNORECASE)
                    if sev_match:
                        current_entry["severity_scores"].append(_severity_to_score(sev_match.group(1)))

                    uri_match = re.search(r"\[uri\s+\"([^\"]+)\"\]", line, flags=re.IGNORECASE)
                    if uri_match and not current_entry.get("uri"):
                        current_entry["uri"] = uri_match.group(1)

                elif line.lower().startswith("stopwatch:"):
                    # Stopwatch: 1753567222593736 6004 (- - -)
                    sw = re.search(r"stopwatch:\s+\d+\s+(\d+)", line, flags=re.IGNORECASE)
                    if sw:
                        current_entry["request_time"] = _safe_float(sw.group(1), 0.0) / 1_000_000.0

    return pd.DataFrame(rows)


def _extract_date_from_text(text: str) -> str:
    # Supports patterns like 2026-03-13, 20260313, or 27-Jul-2025.
    match = re.search(r"(\d{4}[-_]?\d{2}[-_]?\d{2})", text)
    if not match:
        match = re.search(r"(\d{1,2}-[A-Za-z]{3}-\d{4})", text)
        if not match:
            return ""
        return match.group(1)

    raw_date = match.group(1).replace("_", "-")
    if "-" not in raw_date and len(raw_date) == 8:
        return f"{raw_date[0:4]}-{raw_date[4:6]}-{raw_date[6:8]}"
    return raw_date


def _list_supported_log_files(directory: Path) -> list[Path]:
    supported_ext = {".jsonl", ".log", ".json", ".csv"}
    files = [p for p in directory.rglob("*") if p.is_file() and p.suffix.lower() in supported_ext]
    return sorted(files)


def _extract_source_date(file_path: Path) -> str:
    date_from_file = _extract_date_from_text(file_path.name)
    if date_from_file:
        return date_from_file

    for parent in file_path.parents:
        date_from_parent = _extract_date_from_text(parent.name)
        if date_from_parent:
            return date_from_parent
    return ""


def _parse_log_file(file_path: Path) -> pd.DataFrame:
    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("{"):
                return parse_modsecurity_jsonl(file_path)
            break
    return parse_modsecurity_audit_log(file_path)


def load_dataset(dataset_path: str | Path) -> pd.DataFrame:
    """Load CSV, one raw log file, or directory of raw logs split by date."""
    path = Path(dataset_path)

    if path.is_dir():
        files = _list_supported_log_files(path)
        if not files:
            raise ValueError(f"Tidak ada file dataset yang didukung di folder: {path}")

        frames: list[pd.DataFrame] = []
        for file_path in files:
            suffix = file_path.suffix.lower()
            if suffix == ".csv":
                frame = pd.read_csv(file_path)
            else:
                frame = _parse_log_file(file_path)

            frame["source_date"] = _extract_source_date(file_path)
            frames.append(frame)

        return pd.concat(frames, ignore_index=True)

    suffix = path.suffix.lower()

    if suffix in {".csv"}:
        return pd.read_csv(path)

    if suffix in {".jsonl", ".log", ".json"}:
        return _parse_log_file(path)

    raise ValueError(f"Unsupported dataset format: {suffix}")
