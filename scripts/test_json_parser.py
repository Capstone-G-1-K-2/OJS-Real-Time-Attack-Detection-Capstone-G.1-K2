"""Quick test untuk JSON parser dengan sample audit.log."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.modsec_json_parser import parse_modsecurity_json


def test_json_parser():
    """Test JSON parser dengan audit.log file."""
    
    # Try to find audit.log
    audit_log_path = PROJECT_ROOT / "audit.log"
    
    if not audit_log_path.exists():
        print(f"[ERROR] audit.log not found at {audit_log_path}")
        print("\nTrying alternative paths...")
        
        alt_paths = [
            PROJECT_ROOT / "data" / "raw" / "audit.log",
            PROJECT_ROOT / "audit.json",
        ]
        
        for alt in alt_paths:
            if alt.exists():
                audit_log_path = alt
                print(f"[OK] Found at {alt}")
                break
        else:
            print("[ERROR] Could not find audit log file")
            return
    
    print(f"\nTesting JSON parser with: {audit_log_path}")
    print("=" * 60)
    
    try:
        df = parse_modsecurity_json(audit_log_path)
        
        print(f"\n[OK] Successfully parsed {len(df)} transactions")
        print(f"[OK] Columns: {len(df.columns)}")
        
        print("\n[INFO] Column details:")
        print(df.info())
        
        print("\n[INFO] First 3 rows:")
        print(df.head(3))
        
        print("\n[INFO] Label distribution:")
        print(df['label'].value_counts())
        
        print("\n[INFO] Attack types detected:")
        for col in ['has_sqli', 'has_xss', 'has_suspicious_path', 
                    'has_path_traversal', 'has_command_injection']:
            if col in df.columns:
                count = (df[col] == 1).sum()
                print(f"  {col}: {count}")
        
        print("\n[INFO] Sample messages:")
        print(df[df['msg'] != '']['msg'].head(3).tolist())
        
        return df
        
    except Exception as e:
        print(f"\n[ERROR] Failed to parse: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    df = test_json_parser()
