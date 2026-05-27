"""Configuration management for model inference and training."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Load config from JSON file with environment variable overrides."""

    # Config in PROJECT_ROOT/config/model_config.json
    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "model_config.json"

    def __init__(self, config_path: Optional[str] = None):
        """Initialize config from file and environment variables."""
        self.config_path = Path(config_path or self.DEFAULT_CONFIG_PATH)
        # .config di-expose sebagai dict publik agar backward-compatible
        # dengan kode lama yang akses: config.config.get("training", {})
        self.config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load config from JSON file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get(self, key: str, section: str = "inference", default: Any = None) -> Any:
        """Get config value with fallback to default.

        Priority:
        1. Environment variable: MODEL_{SECTION}_{KEY}
        2. Config file: config[section][key]
        3. Default value

        Args:
            key: Config key (e.g., 'threshold')
            section: Config section (e.g., 'inference', 'hyperparameters', 'training')
            default: Default value if key not found

        Returns:
            Config value, environment variable override, or default
        """
        # 1. Check environment variable first (highest priority)
        env_key = f"MODEL_{section.upper()}_{key.upper()}"
        env_value = os.getenv(env_key)
        if env_value is not None:
            # Try to convert to appropriate type
            lowered = env_value.lower()
            if lowered in ("true", "false"):
                return lowered == "true"
            try:
                return float(env_value) if "." in env_value else int(env_value)
            except ValueError:
                return env_value

        # 2. Check config file
        try:
            return self.config[section][key]
        except (KeyError, TypeError):
            return default

    def get_threshold(self) -> float:
        """Get inference threshold with environment override.

        Environment variable: MODEL_INFERENCE_THRESHOLD
        Default: 0.5
        """
        return float(self.get("threshold", section="inference", default=0.5))

    def get_hyperparameters(self) -> Dict[str, Any]:
        """Get all hyperparameters."""
        return self.config.get("hyperparameters", {})

    def get_hyperparameter(self, name: str, default: Any = None) -> Any:
        """Get single hyperparameter with environment override.

        Environment variable: MODEL_HYPERPARAMETERS_{NAME}
        """
        return self.get(name, section="hyperparameters", default=default)

    def to_dict(self) -> Dict[str, Any]:
        """Export config as dict."""
        return self.config.copy()

    def __repr__(self) -> str:
        return f"Config(path={self.config_path}, threshold={self.get_threshold()})"


def get_config(config_path: Optional[str] = None) -> Config:
    """Convenience function to get Config instance."""
    return Config(config_path=config_path)


# Example usage:
if __name__ == "__main__":
    # Load from default location
    cfg = get_config()

    print("Config loaded:")
    print(f"  Threshold: {cfg.get_threshold()}")
    print(f"  N-Estimators: {cfg.get_hyperparameter('n_estimators')}")
    print(f"  Max Depth: {cfg.get_hyperparameter('max_depth')}")
    print()
    print("To override with environment variables:")
    print("  export MODEL_INFERENCE_THRESHOLD=0.4")
    print("  export MODEL_HYPERPARAMETERS_N_ESTIMATORS=300")
    print()
    print("Full config:")
    print(json.dumps(cfg.to_dict(), indent=2))