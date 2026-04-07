#!/usr/bin/env python3
"""Test versioning system dan daily retraining."""

from __future__ import annotations

import sys
from pathlib import Path
import json

# Setup path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.model_versioning import ModelVersionManager


def test_version_manager():
    """Test ModelVersionManager functionality."""
    print("\n" + "="*60)
    print("TEST: Model Versioning System")
    print("="*60)
    
    # Initialize
    print("\n1️⃣  Initialize ModelVersionManager")
    mgr = ModelVersionManager(model_dir="models/trained_models")
    print("   ✓ Initialized")
    
    # Get current version
    print("\n2️⃣  Get current version")
    current = mgr.get_current_version()
    print(f"   Current version: {current}")
    
    # Get model path
    print("\n3️⃣  Get model path for current version")
    model_path = mgr.get_model_path()
    print(f"   Path: {model_path}")
    print(f"   Exists: {model_path.exists()}")
    
    # List all versions
    print("\n4️⃣  List all versions")
    versions = mgr.list_all_versions()
    print(f"   Total versions: {len(versions)}")
    for v in versions:
        print(f"     v{v['version']}: {v['created_at']}")
        print(f"       Accuracy: {v['metrics']['accuracy']:.4f}")
    
    # Get version info
    if versions:
        print("\n5️⃣  Get info for latest version")
        latest = versions[-1]
        info = mgr.get_version_info(latest['version'])
        print(f"   Version {info['version']}:")
        print(f"     Created: {info['created_at']}")
        print(f"     Accuracy: {info['metrics']['accuracy']:.4f}")
        print(f"     F1-Score: {info['metrics']['f1_score']:.4f}")
        print(f"     Samples: {info['training_data']['samples']}")
    
    # Compare versions (if more than 1)
    if len(versions) >= 2:
        print("\n6️⃣  Compare last 2 versions")
        v1_num = versions[-2]['version']
        v2_num = versions[-1]['version']
        comparison = mgr.compare_versions(v1_num, v2_num)
        print(f"   V{v1_num} vs V{v2_num}:")
        print(f"     Accuracy improvement: {comparison['improvements']['accuracy']:.4f}")
        print(f"     F1-Score improvement: {comparison['improvements']['f1_score']:.4f}")
    
    # Print summary
    print("\n7️⃣  Version summary")
    print("   (This is what you'd call mgr.print_version_summary())")
    mgr.print_version_summary()
    
    print("="*60)
    print("✓ All tests passed!")
    print("="*60 + "\n")
    
    return True


def test_daily_retrain_import():
    """Test daily_retrain.py imports correctly."""
    print("\n" + "="*60)
    print("TEST: Daily Retrain Script")
    print("="*60)
    
    try:
        # Try importing
        print("\n1️⃣  Checking imports...")
        import pandas as pd
        print("   ✓ pandas")
        from sklearn.pipeline import Pipeline
        print("   ✓ sklearn.pipeline")
        from xgboost import XGBClassifier
        print("   ✓ xgboost")
        from src.preprocessing.modsec_parser import load_dataset
        print("   ✓ modsec_parser")
        from src.utils.model_versioning import ModelVersionManager
        print("   ✓ model_versioning")
        
        # Check script exists
        print("\n2️⃣  Check daily_retrain.py exists")
        script_path = PROJECT_ROOT / "scripts" / "daily_retrain.py"
        if script_path.exists():
            print(f"   ✓ Found: {script_path}")
        else:
            print(f"   ✗ Not found: {script_path}")
            return False
        
        # Check scheduler exists
        print("\n3️⃣  Check scheduler_daily_retrain.py exists")
        scheduler_path = PROJECT_ROOT / "scripts" / "scheduler_daily_retrain.py"
        if scheduler_path.exists():
            print(f"   ✓ Found: {scheduler_path}")
        else:
            print(f"   ✗ Not found: {scheduler_path}")
            return False
        
        print("\n" + "="*60)
        print("✓ All checks passed!")
        print("="*60 + "\n")
        return True
    
    except ImportError as e:
        print(f"   ✗ Import error: {e}")
        return False


def check_api_updates():
    """Test API main.py has been updated."""
    print("\n" + "="*60)
    print("TEST: API Updates")
    print("="*60)
    
    try:
        print("\n1️⃣  Check API imports versioning module")
        api_file = PROJECT_ROOT / "src" / "api" / "main.py"
        with open(api_file) as f:
            content = f.read()
            if "ModelVersionManager" in content:
                print("   ✓ ModelVersionManager imported")
            else:
                print("   ✗ ModelVersionManager not imported")
                return False
            
            if "_load_model" in content:
                print("   ✓ _load_model function exists")
            else:
                print("   ✗ _load_model function not found")
                return False
            
            if "/admin/versions" in content:
                print("   ✓ /admin/versions endpoint added")
            else:
                print("   ✗ /admin/versions endpoint not found")
                return False
            
            if "/admin/rollback" in content:
                print("   ✓ /admin/rollback endpoint added")
            else:
                print("   ✗ /admin/rollback endpoint not found")
                return False
        
        print("\n" + "="*60)
        print("✓ All API checks passed!")
        print("="*60 + "\n")
        return True
    
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "█"*60)
    print("DAILY RETRAINING SYSTEM - VALIDATION TESTS")
    print("█"*60)
    
    all_passed = True
    
    # Test 1
    try:
        if not test_version_manager():
            all_passed = False
    except Exception as e:
        print(f"✗ Version manager test failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    # Test 2
    try:
        if not test_daily_retrain_import():
            all_passed = False
    except Exception as e:
        print(f"✗ Daily retrain test failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    # Test 3
    try:
        if not check_api_updates():
            all_passed = False
    except Exception as e:
        print(f"✗ API test failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    # Summary
    print("\n" + "█"*60)
    if all_passed:
        print("✓ ALL TESTS PASSED!")
        print("█"*60)
        print("\nYour daily retraining system is ready to use!")
        print("\nNext steps:")
        print("1. python scripts/daily_retrain.py --dataset ...")
        print("   (Test manual retraining first)")
        print("\n2. python scripts/scheduler_daily_retrain.py --time 02:00")
        print("   (Setup automatic daily retraining)")
        print("\n3. Monitor: tail -f logs/retraining_scheduler.log")
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        print("█"*60)
        print("\nPlease fix issues and retry.")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
