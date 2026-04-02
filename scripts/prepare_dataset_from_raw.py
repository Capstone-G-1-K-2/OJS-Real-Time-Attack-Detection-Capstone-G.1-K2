"""Prepare labeled dataset from raw ModSecurity text audit logs."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.modsec_text_parser import load_all_modsec_logs


def main() -> None:
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Prepare labeled dataset from raw ModSecurity logs."
    )
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--output", default="data/dataset/modsec_raw_processed.csv")
    args = parser.parse_args()
    
    print("=" * 60)
    print("PREPARING DATASET FROM RAW LOGS")
    print("=" * 60)
    
    # Load all logs
    print("\n[STEP 1] Parsing all ModSecurity text logs...")
    df = load_all_modsec_logs(args.raw_dir)
    print(f"\n[OK] Loaded {len(df)} transactions")
    print(f"[OK] Columns: {len(df.columns)}")
    
    # Label distribution
    print("\n[STEP 2] Label distribution:")
    if 'label' in df.columns:
        dist = df['label'].value_counts().sort_index()
        print(dist)
        if len(dist) > 0:
            pct = dist.get(1, 0) / len(df) * 100 if len(df) > 0 else 0
            print(f"Attack ratio: {pct:.2f}%")
    
    # Add features
    if 'uri' in df.columns:
        print("\n[STEP 3] Adding features...")
        df['uri_len'] = df['uri'].str.len()
        df['has_sqli'] = df['uri'].str.lower().str.contains(
            r'union|select|sleep|drop|exec', na=False
        ).astype(int)
        df['has_xss'] = df['uri'].str.lower().str.contains(
            r'<script|javascript|onerror|alert', na=False
        ).astype(int)
        print(f"[OK] Added feature columns")
    
    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    
    print("\n" + "=" * 60)
    print("COMPLETE")
    print("=" * 60)
    print(f"Saved to: {output_path}")
    print(f"Rows: {len(df)}, Columns: {len(df.columns)}")


if __name__ == "__main__":
    main()
