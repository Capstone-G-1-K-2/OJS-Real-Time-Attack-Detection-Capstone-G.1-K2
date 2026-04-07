"""Pipeline orchestrator for predictions and alerting."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd

from src.preprocessing.tabular_features import build_tabular_features
from src.alerts.telegram_notifier import TelegramNotifier

logger = logging.getLogger(__name__)


class PredictionPipeline:
    """Orchestrate predictions, feature building, and alerts."""
    
    def __init__(
        self,
        model_path: str,
        alert_threshold: float = 0.5,
        severity_threshold: float = 0.7,
    ):
        """
        Initialize pipeline.
        
        Args:
            model_path: Path to trained model
            alert_threshold: Probability threshold for alerting
            severity_threshold: Threshold for high severity classification
        """
        self.model_path = model_path
        self.model = None
        self.alert_threshold = alert_threshold
        self.severity_threshold = severity_threshold
        self.notifier = None
        
        self._load_model()
        self._init_notifier()
    
    def _load_model(self):
        """Load trained model."""
        try:
            if Path(self.model_path).exists():
                self.model = joblib.load(self.model_path)
                logger.info(f"✓ Model loaded: {self.model_path}")
            else:
                logger.warning(f"Model not found: {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def _init_notifier(self):
        """Initialize Telegram notifier."""
        try:
            self.notifier = TelegramNotifier()
            if self.notifier.is_configured():
                logger.info("✓ Telegram notifier ready")
        except Exception as e:
            logger.warning(f"Notifier init failed: {e}")
    
    def predict(self, df: pd.DataFrame, return_features: bool = False) -> dict:
        """
        Predict on batch of logs.
        
        Args:
            df: DataFrame with log data
            return_features: Include engineered features in output
        
        Returns:
            {
                'predictions': array of 0/1,
                'probabilities': array of probabilities,
                'features': features used (if return_features=True),
                'attacks': list of detected attacks
            }
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        if df.empty:
            raise ValueError("Input DataFrame is empty")
        
        try:
            # Build features
            features = build_tabular_features(df)
            
            # Predict
            probs = self.model.predict_proba(features)[:, 1]
            preds = self.model.predict(features)
            
            # Extract attacks
            attack_indices = [i for i, p in enumerate(preds) if p == 1]
            attacks = []
            
            for idx in attack_indices:
                attacks.append({
                    "index": idx,
                    "method": df.iloc[idx].get("method", ""),
                    "uri": df.iloc[idx].get("uri", ""),
                    "probability": float(probs[idx]),
                    "severity": self._classify_severity(probs[idx]),
                })
            
            result = {
                "predictions": preds,
                "probabilities": probs,
                "attacks": attacks,
            }
            
            if return_features:
                result["features"] = features
            
            return result
        
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            raise
    
    def _classify_severity(self, probability: float) -> str:
        """Classify attack severity based on probability."""
        if probability < 0.6:
            return "low"
        elif probability < 0.8:
            return "medium"
        else:
            return "high"
    
    async def predict_and_alert(
        self,
        df: pd.DataFrame,
        send_alert: bool = True,
        alert_title: str = "Attack Detected",
    ) -> dict:
        """
        Predict and send alert if attacks detected.
        
        Args:
            df: Input logs
            send_alert: Whether to send Telegram alert
            alert_title: Title for alert
        
        Returns:
            Prediction results with alert status
        """
        result = self.predict(df)
        
        attacks = result.get("attacks", [])
        alert_sent = False
        
        if attacks and send_alert and self.notifier and self.notifier.is_configured():
            try:
                # Build alert message
                top_attacks = [
                    f"{a['method']} {a['uri']} ({a['severity'].upper()})"
                    for a in attacks[:3]
                ]
                
                message = "\n".join(top_attacks)
                
                await self.notifier.send_alert(
                    title=alert_title,
                    message=message,
                    severity=max(
                        (a.get("severity", "medium") for a in attacks),
                        default="medium",
                        key=lambda s: {"low": 1, "medium": 2, "high": 3}.get(s, 0),
                    ),
                    attack_count=len(attacks),
                )
                alert_sent = True
            except Exception as e:
                logger.error(f"Alert sending failed: {e}")
        
        result["alert_sent"] = alert_sent
        return result
