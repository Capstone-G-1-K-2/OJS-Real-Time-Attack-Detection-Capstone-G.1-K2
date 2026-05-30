import pandas as pd
import numpy as np

def merge_datasets():
    old_file = 'modsec_raw_json_v2.csv'
    new_file = 'modsec_events.csv'
    output_file = 'modsec_merged.csv'

    print("Loading old dataset...")
    df_old = pd.read_csv(old_file)
    print(f"Old dataset shape: {df_old.shape}")

    print("Loading new dataset (from Adminer)...")
    # New dataset has no header, 36 columns.
    # We map columns 2-30 (0-indexed) to the 29 columns of the old dataset
    # 0: id, 1: transaction_id?, 2: timestamp ... 30: label
    new_cols_full = [
        'id', 'transaction_id', 'timestamp', 'source_ip', 'method', 'uri', 'status', 'bytes_sent',
        'request_time', 'user_agent', 'user_agent_len', 'uri_len', 'severity', 'severity_score',
        'rule_id', 'matched_data', 'msg', 'is_blocked', 'rule_count', 'has_sqli', 'has_xss',
        'has_suspicious_path', 'has_path_traversal', 'has_command_injection', 'has_cve_2022_24181',
        'missing_csrf_token', 'has_suspicious_referer', 'has_cve_2024_xss_privesc', 'has_privesc_attempt',
        'has_cve_2021_32626', 'label', 'pred_score', 'is_alerted', 'alert_channel', 'created_at', 'updated_at'
    ]
    
    # Read the new CSV
    df_new = pd.read_csv(new_file, header=None, names=new_cols_full)
    
    # Select only the columns that exist in the old dataset
    cols_to_keep = list(df_old.columns)
    df_new_subset = df_new[cols_to_keep].copy()
    print(f"New dataset shape (matching columns): {df_new_subset.shape}")

    # Standardize timestamp formats
    print("Standardizing timestamps...")
    # df_old format: Tue May  5 04:12:06 2026
    df_old['timestamp'] = pd.to_datetime(df_old['timestamp'], errors='coerce')
    # df_new format: 2026-05-18 13:25:54
    df_new_subset['timestamp'] = pd.to_datetime(df_new_subset['timestamp'], errors='coerce')

    # Normalize is_blocked column (if needed, map 0/1 to False/True or just keep 0/1)
    df_old['is_blocked'] = df_old['is_blocked'].astype(bool)
    df_new_subset['is_blocked'] = df_new_subset['is_blocked'].astype(bool)

    print("Concatenating datasets...")
    df_merged = pd.concat([df_old, df_new_subset], ignore_index=True)
    
    initial_shape = df_merged.shape
    print(f"Merged dataset shape before deduplication: {initial_shape}")
    
    # Drop duplicates
    # Since timestamps are now standard pandas datetime, duplicates should be perfectly matched 
    # if they overlap.
    df_merged = df_merged.drop_duplicates()
    final_shape = df_merged.shape
    print(f"Merged dataset shape after deduplication: {final_shape}")
    print(f"Dropped {initial_shape[0] - final_shape[0]} duplicate rows.")

    # Save to CSV
    print(f"Saving merged dataset to {output_file}...")
    df_merged.to_csv(output_file, index=False)
    print("Done!")

if __name__ == "__main__":
    merge_datasets()
