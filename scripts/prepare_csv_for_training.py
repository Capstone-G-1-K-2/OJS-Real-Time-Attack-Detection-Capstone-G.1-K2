"""Convert labeled_dataset.csv to training format with extracted features."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pandas as pd

# Make src importable when running script directly
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.pattern_rules import (
    SQLI_PATTERNS,
    XSS_PATTERNS,
    SUSPICIOUS_PATH_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
)


def _contains_pattern(text: str, patterns: list[str]) -> int:
    """Check if text contains any pattern."""
    if not isinstance(text, str):
        return 0
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return 1
    return 0


def _extract_severity_from_anomaly_score(score: float) -> int:
    """Convert anomaly score to severity score (0-5).
    
    Mapping:
    0-2: INFO (0)
    3-6: NOTICE (1)
    7-12: WARNING (2)
    13-20: ERROR (3)
    21-26: CRITICAL (4)
    27+: EMERGENCY (5)
    """
    if pd.isna(score):
        return 0
    score = float(score)
    if score < 3:
        return 0
    elif score < 7:
        return 1
    elif score < 13:
        return 2
    elif score < 21:
        return 3
    elif score < 27:
        return 4
    else:
        return 5


def prepare_csv_for_training(input_path: str | Path, output_path: str | Path) -> None:
    """Prepare CSV data for training by extracting required features."""
    print(f"[INFO] Loading data from: {input_path}")
    df = pd.read_csv(input_path)

    print(f"[INFO] Original data shape: {df.shape}")
    print(f"[INFO] Columns: {df.columns.tolist()}")

    # 1. Convert label: 'normal' -> 0, 'malicious' -> 1
    df["label"] = (df["label"] == "malicious").astype(int)

    # 2. Use uri_norm as uri (clean/normalized version)
    df["uri"] = df["uri_norm"]

    # 3. Extract features from uri and attack_tags
    df["uri_len"] = df["uri"].apply(lambda x: len(str(x)))
    df["has_sqli_pattern"] = df.apply(
        lambda row: _contains_pattern(str(row["uri_full"]), SQLI_PATTERNS), axis=1
    )
    df["has_xss_pattern"] = df.apply(
        lambda row: _contains_pattern(str(row["uri_full"]), XSS_PATTERNS), axis=1
    )
    df["has_suspicious_path"] = df.apply(
        lambda row: _contains_pattern(str(row["uri"]), SUSPICIOUS_PATH_PATTERNS), axis=1
    )
    df["has_path_traversal"] = df.apply(
        lambda row: _contains_pattern(str(row["uri"]), PATH_TRAVERSAL_PATTERNS), axis=1
    )
    df["has_command_injection"] = df.apply(
        lambda row: _contains_pattern(str(row["uri"]), COMMAND_INJECTION_PATTERNS), axis=1
    )

    # 4. Convert anomaly_score to severity_score
    df["severity_score"] = df["anomaly_score"].apply(_extract_severity_from_anomaly_score)

    # 5. Set default values for missing features
    df["bytes_sent"] = 0  # Not available in CSV, use default
    df["request_time"] = 0.0  # Not available in CSV, use default
    df["rule_count"] = 0  # Not available in CSV, use default (could be derived from attack_tags)
    df["user_agent_len"] = 0  # Not available in CSV, use default

    # 6. Ensure method is present
    if "method" not in df.columns:
        df["method"] = "GET"

    # 7. Select only required columns for training
    required_columns = [
        "method",
        "uri",
        "status",
        "bytes_sent",
        "request_time",
        "rule_count",
        "severity_score",
        "user_agent_len",
        "uri_len",
        "has_sqli_pattern",
        "has_xss_pattern",
        "has_suspicious_path",
        "label",
    ]

    df_train = df[required_columns].copy()

    # Ensure correct data types
    df_train["method"] = df_train["method"].astype(str)
    df_train["uri"] = df_train["uri"].astype(str)
    df_train["status"] = df_train["status"].astype(int)
    df_train["bytes_sent"] = df_train["bytes_sent"].astype(int)
    df_train["request_time"] = df_train["request_time"].astype(float)
    df_train["rule_count"] = df_train["rule_count"].astype(int)
    df_train["severity_score"] = df_train["severity_score"].astype(int)
    df_train["user_agent_len"] = df_train["user_agent_len"].astype(int)
    df_train["uri_len"] = df_train["uri_len"].astype(int)
    df_train["has_sqli_pattern"] = df_train["has_sqli_pattern"].astype(int)
    df_train["has_xss_pattern"] = df_train["has_xss_pattern"].astype(int)
    df_train["has_suspicious_path"] = df_train["has_suspicious_path"].astype(int)
    df_train["label"] = df_train["label"].astype(int)

    # Save
    print(f"[INFO] Saving prepared data to: {output_path}")
    df_train.to_csv(output_path, index=False)

    print(f"[INFO] ✓ Prepared data saved successfully!")
    print(f"[INFO] Output shape: {df_train.shape}")
    print(f"[INFO] Label distribution:\n{df_train['label'].value_counts()}")
    print(f"[INFO] Columns in output: {df_train.columns.tolist()}")

    # Print sample
    print(f"\n[INFO] Sample rows:")
    print(df_train.head(3))


def main():
    parser = argparse.ArgumentParser(
        description="Prepare CSV data for training by extracting required features"
    )
    parser.add_argument(
        "--input",
        default="data/dataset/labeled_dataset.csv",
        help="Input CSV file path",
    )
    parser.add_argument(
        "--output",
        default="data/dataset/labeled_dataset_prepared.csv",
        help="Output CSV file path",
    )
    args = parser.parse_args()

    prepare_csv_for_training(args.input, args.output)


if __name__ == "__main__":
    main()
