from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from src.preprocessing.modsec_json_parser import parse_modsecurity_json


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


def _extract_source_date(file_path: Path) -> str:
    date_from_file = _extract_date_from_text(file_path.name)
    if date_from_file:
        return date_from_file

    for parent in file_path.parents:
        date_from_parent = _extract_date_from_text(parent.name)
        if date_from_parent:
            return date_from_parent
    return ""


def _list_supported_log_files(directory: Path) -> list[Path]:
    supported_ext = {".jsonl", ".log", ".json", ".csv"}
    files = [p for p in directory.rglob("*") if p.is_file() and p.suffix.lower() in supported_ext]
    return sorted(files)


def _parse_json_log_file(file_path: Path) -> pd.DataFrame:
    # JSON-only mode: .log is treated as JSON/JSONL modsecurity export.
    return parse_modsecurity_json(file_path)


def load_dataset(dataset_path: str | Path) -> pd.DataFrame:
    """Load CSV, one JSON raw log file, or directory of JSON logs split by date.

    JSON-only mode:
    - Supported raw formats: JSONL, JSON array, single JSON object
    - Supported extensions: .jsonl, .json, .log (if content is JSON)
    """
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
                frame = _parse_json_log_file(file_path)

            frame["source_date"] = _extract_source_date(file_path)
            frames.append(frame)

        return pd.concat(frames, ignore_index=True)

    suffix = path.suffix.lower()

    if suffix == ".csv":
        return pd.read_csv(path)

    if suffix in {".jsonl", ".log", ".json"}:
        return _parse_json_log_file(path)

    raise ValueError(f"Unsupported dataset format: {suffix}")
