"""Model versioning management system."""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class ModelVersionManager:
    """Manage model versions and track training history."""
    
    def __init__(self, model_dir: str = "models/trained_models"):
        """Initialize version manager.
        
        Args:
            model_dir: Directory where models are stored
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # File untuk tracking versi
        self.version_file = self.model_dir / "versions.json"
        self.current_version_file = self.model_dir / "current_version.txt"
        
        # Ensure files exist
        if not self.version_file.exists():
            self._init_versions_file()
        
        if not self.current_version_file.exists():
            self._init_current_version()
    
    def _init_versions_file(self):
        """Initialize versions tracking file."""
        versions = {
            "all_versions": [],
            "last_updated": None
        }
        with open(self.version_file, 'w') as f:
            json.dump(versions, f, indent=2)
        logger.info("✓ Created versions.json")
    
    def _init_current_version(self):
        """Initialize current version file."""
        with open(self.current_version_file, 'w') as f:
            f.write("1")
        logger.info("✓ Created current_version.txt (starting at v1)")
    
    def create_new_version(
        self,
        accuracy: float,
        f1_score: float,
        precision: float,
        recall: float,
        data_samples: int,
        notes: str = ""
    ) -> int:
        """
        Create a new model version.
        
        Apa yang terjadi:
        1. Get next version number (v1 → v2 → v3, etc)
        2. Save model metadata ke versions.json
        3. Track kapan model dibuat, metrics-nya, dll
        4. Return version number
        
        Args:
            accuracy: Model accuracy score
            f1_score: F1 score
            precision: Precision score
            recall: Recall score
            data_samples: How many samples used for training
            notes: Additional notes about this version
        
        Returns:
            Version number (int)
        """
        # Load current versions
        with open(self.version_file, 'r') as f:
            versions_data = json.load(f)
        
        # Get next version number
        all_versions = versions_data.get("all_versions", [])
        next_version = len(all_versions) + 1
        
        # Create version metadata
        version_info = {
            "version": next_version,
            "filename": f"modsec_xgb_v{next_version}.pkl",
            "created_at": datetime.now().isoformat(),
            "metrics": {
                "accuracy": accuracy,
                "f1_score": f1_score,
                "precision": precision,
                "recall": recall
            },
            "training_data": {
                "samples": data_samples
            },
            "notes": notes,
            "status": "active"
        }
        
        # Add to all versions
        all_versions.append(version_info)
        
        # Update tracking file
        versions_data["all_versions"] = all_versions
        versions_data["last_updated"] = datetime.now().isoformat()
        
        with open(self.version_file, 'w') as f:
            json.dump(versions_data, f, indent=2)
        
        # Update current version
        with open(self.current_version_file, 'w') as f:
            f.write(str(next_version))
        
        logger.info(f"✓ Version {next_version} created")
        logger.info(f"  Accuracy: {accuracy:.4f}")
        logger.info(f"  F1-Score: {f1_score:.4f}")
        
        return next_version
    
    def get_current_version(self) -> int:
        """Get current active version."""
        with open(self.current_version_file, 'r') as f:
            version = int(f.read().strip())
        return version
    
    def get_model_path(self, version: Optional[int] = None) -> Path:
        """
        Get path to model file.
        
        Args:
            version: Version number (None = current version)
        
        Returns:
            Path to pickle file
        """
        if version is None:
            version = self.get_current_version()
        
        model_path = self.model_dir / f"modsec_xgb_v{version}.pkl"
        return model_path
    
    def list_all_versions(self) -> list:
        """List all models that exist."""
        with open(self.version_file, 'r') as f:
            versions_data = json.load(f)
        
        return versions_data.get("all_versions", [])
    
    def get_version_info(self, version: int) -> dict:
        """Get info about specific version."""
        versions = self.list_all_versions()
        for v in versions:
            if v["version"] == version:
                return v
        return None
    
    def get_latest_metrics(self) -> dict:
        """Get metrics of current active version."""
        current = self.get_current_version()
        info = self.get_version_info(current)
        if info:
            return info.get("metrics", {})
        return {}
    
    def compare_versions(self, v1: int, v2: int) -> dict:
        """Compare two versions."""
        info1 = self.get_version_info(v1)
        info2 = self.get_version_info(v2)
        
        if not info1 or not info2:
            return {}
        
        return {
            "v1": {
                "version": v1,
                "metrics": info1.get("metrics", {}),
                "created_at": info1.get("created_at")
            },
            "v2": {
                "version": v2,
                "metrics": info2.get("metrics", {}),
                "created_at": info2.get("created_at")
            },
            "improvements": {
                "accuracy": info2["metrics"]["accuracy"] - info1["metrics"]["accuracy"],
                "f1_score": info2["metrics"]["f1_score"] - info1["metrics"]["f1_score"],
            }
        }
    
    def rollback_to_version(self, version: int) -> bool:
        """
        Rollback ke versi lama.
        
        Scenario: Model baru v3 ternyata jelek, mau balik ke v2.
        Fungsi ini update current_version.txt → v2
        API akan load v2 pada restart.
        
        Args:
            version: Version number to rollback to
        
        Returns:
            True jika rollback sukses
        """
        # Check version exists
        info = self.get_version_info(version)
        if not info:
            logger.error(f"Version {version} not found")
            return False
        
        # Check file exists
        model_path = self.get_model_path(version)
        if not model_path.exists():
            logger.error(f"Model file not found: {model_path}")
            return False
        
        # Update current version
        with open(self.current_version_file, 'w') as f:
            f.write(str(version))
        
        logger.info(f"✓ Rolled back to version {version}")
        logger.info(f"  Please restart API server to apply changes")
        
        return True
    
    def print_version_summary(self):
        """Print summary of all versions."""
        versions = self.list_all_versions()
        current = self.get_current_version()
        
        print("\n" + "="*60)
        print("MODEL VERSION HISTORY")
        print("="*60)
        
        for v in versions:
            marker = "→" if v["version"] == current else " "
            print(f"\n{marker} Version {v['version']}")
            print(f"  Created: {v['created_at']}")
            print(f"  Accuracy: {v['metrics']['accuracy']:.4f}")
            print(f"  F1-Score: {v['metrics']['f1_score']:.4f}")
            print(f"  Samples: {v['training_data']['samples']}")
            if v.get('notes'):
                print(f"  Notes: {v['notes']}")
        
        print(f"\n✓ Current active version: {current}")
        print("="*60 + "\n")
