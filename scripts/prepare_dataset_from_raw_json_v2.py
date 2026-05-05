"""Prepare labeled dataset from raw ModSecurity JSON audit logs - VERSION 2."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.modsec_json_parser import load_modsec_json_log


def main() -> None:
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Prepare labeled dataset from raw ModSecurity JSON logs (VERSION 2)."
    )
    parser.add_argument(
        "--input",
        default="data/raw/audit.log",
        help="Path ke JSON log file (default: data/raw/audit.log)"
    )
    parser.add_argument(
        "--output",
        default="data/dataset/modsec_raw_json_v2.csv",
        help="Path output CSV file"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("PREPARING DATASET FROM RAW JSON LOGS (VERSION 2)")
    print("=" * 60)
    
    # Check input file
    input_file = Path(args.input)
    if not input_file.exists():
        print(f"\n[ERROR] File not found: {input_file}")
        print(f"\nUsage:")
        print(f"  python scripts/prepare_dataset_from_raw_json_v2.py --input /path/to/audit.log")
        print(f"\nDefault fallback: data/raw/audit.log")
        return
    
    # Load logs
    print("\n[STEP 1] Parsing ModSecurity JSON log...")
    try:
        df = load_modsec_json_log(args.input)
        print(f"[OK] Loaded {len(df)} transactions")
        print(f"[OK] Columns: {len(df.columns)}")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        return
    
    # Label distribution
    print("\n[STEP 2] Label distribution:")
    if 'label' in df.columns:
        dist = df['label'].value_counts().sort_index()
        print(dist)
        if len(dist) > 0:
            pct = dist.get(1, 0) / len(df) * 100 if len(df) > 0 else 0
            print(f"Attack ratio: {pct:.2f}%")
    else:
        print("[WARN] 'label' column not found")
    
    # Show some stats
    print("\n[STEP 3] Data statistics:")
    print(f"Unique source IPs: {df['source_ip'].nunique() if 'source_ip' in df.columns else 'N/A'}")
    print(f"HTTP methods: {df['method'].unique() if 'method' in df.columns else 'N/A'}")
    
    if 'uri' in df.columns:
        print(f"Unique URIs: {df['uri'].nunique()}")
        print(f"Top 5 URIs:")
        print(df['uri'].value_counts().head())
    
    # Feature flags
    print("\n[STEP 4] Feature flags distribution:")
    feature_cols = [
        'has_sqli', 'has_xss', 'has_suspicious_path',
        'has_path_traversal', 'has_command_injection'
    ]
    for col in feature_cols:
        if col in df.columns:
            count = (df[col] == 1).sum()
            pct = count / len(df) * 100 if len(df) > 0 else 0
            print(f"  {col}: {count} ({pct:.2f}%)")
    
    # Add additional features if not present
    print("\n[STEP 5] Adding derived features...")
    if 'uri' in df.columns and 'uri_len' not in df.columns:
        df['uri_len'] = df['uri'].str.len()
    
    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    
    print("\n" + "=" * 60)
    print("COMPLETE")
    print("=" * 60)
    print(f"Saved to: {output_path}")
    print(f"Rows: {len(df)}, Columns: {len(df.columns)}")
    print("\nColumns:")
    for i, col in enumerate(df.columns, 1):
        dtype = str(df[col].dtype)
        print(f"  {i:2d}. {col:<25s} ({dtype})")


if __name__ == "__main__":
    main()
