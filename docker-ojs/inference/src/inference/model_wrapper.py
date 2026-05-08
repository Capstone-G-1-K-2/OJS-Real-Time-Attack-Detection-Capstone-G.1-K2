from __future__ import annotations

import pickle
from typing import Any, Dict

import pandas as pd

from src.preprocessing.modsec_json_parser import _extract_from_json_transaction


class ModelWrapper:
    """Wrap a trained sklearn pipeline so it accepts raw ModSecurity JSON transactions.

    Usage:
        wrapper = ModelWrapper.from_pipeline(pipeline)
        wrapper.predict_from_json(tx)
    Or load previously saved wrapper via pickle.
    """

    def __init__(self, pipeline: Any):
        self.pipeline = pipeline

    @classmethod
    def from_pickle(cls, path: str) -> "ModelWrapper":
        with open(path, "rb") as f:
            pipeline = pickle.load(f)
        return cls(pipeline)

    @classmethod
    def from_pipeline(cls, pipeline: Any) -> "ModelWrapper":
        return cls(pipeline)

    def _normalize_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        # Rename parser-specific keys to pipeline expected names
        if "has_sqli" in row and "has_sqli_pattern" not in row:
            row["has_sqli_pattern"] = row.pop("has_sqli")
        if "has_xss" in row and "has_xss_pattern" not in row:
            row["has_xss_pattern"] = row.pop("has_xss")

        # Features expected by the training pipeline
        numeric_features = [
            "status",
            "bytes_sent",
            "request_time",
            "user_agent_len",
            "uri_len",
            "has_sqli_pattern",
            "has_xss_pattern",
            "has_suspicious_path",
            "has_path_traversal",
            "has_command_injection",
            "has_cve_2022_24181",
            "missing_csrf_token",
            "has_suspicious_referer",
            "has_cve_2024_xss_privesc",
            "has_privesc_attempt",
            "has_cve_2021_32626",
        ]

        # Ensure all expected numeric features exist
        for feat in numeric_features:
            if feat not in row:
                row[feat] = 0

        # Ensure categorical and text features exist
        if "method" not in row:
            row["method"] = "GET"
        if "uri" not in row:
            row["uri"] = "/"

        return row

    def predict_from_json(self, tx: Dict[str, Any], threshold: float = 0.5) -> Dict[str, Any]:
        """Accept a single ModSecurity transaction (dict), return prediction + probability.

        Returns: {"prediction": 0|1, "probability": float, "decision": "NORMAL"|"ATTACK"}
        """
        row = _extract_from_json_transaction(tx)
        row = self._normalize_row(row)
        df = pd.DataFrame([row])

        # Pipeline should handle preprocessing (OneHot, TF-IDF)
        if hasattr(self.pipeline, "predict_proba"):
            prob = float(self.pipeline.predict_proba(df)[:, 1][0])
        else:
            prob = None

        if prob is not None:
            pred = int(prob >= threshold)
        else:
            pred = int(self.pipeline.predict(df)[0])

        return {
            "prediction": pred,
            "probability": prob,
            "decision": "ATTACK" if pred == 1 else "NORMAL",
            "threshold": threshold,
        }

    def predict_batch_from_json(self, txs: list[Dict[str, Any]], threshold: float = 0.5) -> list[Dict[str, Any]]:
        rows = [self._normalize_row(_extract_from_json_transaction(tx)) for tx in txs]
        df = pd.DataFrame(rows)
        probs = None
        if hasattr(self.pipeline, "predict_proba"):
            probs = self.pipeline.predict_proba(df)[:, 1]
        preds = self.pipeline.predict(df) if probs is None else (probs >= threshold).astype(int)

        results = []
        for i, _ in enumerate(rows):
            p = float(probs[i]) if probs is not None else None
            pr = int(preds[i])
            results.append({
                "prediction": pr,
                "probability": p,
                "decision": "ATTACK" if pr == 1 else "NORMAL",
                "threshold": threshold,
            })
        return results
