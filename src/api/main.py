"""FastAPI application for real-time attack detection (OJS-agnostic)."""

from __future__ import annotations

import logging
import pickle
import sys
from pathlib import Path
from typing import Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

# Setup path for imports
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.api.models import (
    AlertRequest,
    BatchLogRequest,
    HealthResponse,
    LogRequest,
    PredictionResponse,
    PredictionResult,
)
from src.preprocessing.tabular_features import build_tabular_features
from src.alerts.telegram_notifier import TelegramNotifier
from src.utils.model_versioning import ModelVersionManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="OJS Attack Detection API",
    description="Real-time ML-based attack detection for HTTP logs (OJS-agnostic)",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model state
MODEL = None
MODEL_VERSION = None
MODEL_DIR = str(PROJECT_ROOT / "models/trained_models")
VERSION_MANAGER = None
NOTIFIER: Optional[TelegramNotifier] = None


def _load_model():
    """
    Load trained model on startup dengan versioning support.
    
    Alur:
    1. Initialize ModelVersionManager
    2. Get current active version dari current_version.txt
    3. Load model file untuk versi tersebut
    4. Log versi dan path
    
    Jadi kalau ada model v1, v2, v3, API akan otomatis load
    model yang active (ditentukan oleh current_version.txt).
    """
    global MODEL, MODEL_VERSION, VERSION_MANAGER
    try:
        # Initialize version manager
        VERSION_MANAGER = ModelVersionManager(model_dir=MODEL_DIR)
        
        # Get current version
        current_version = VERSION_MANAGER.get_current_version()
        MODEL_VERSION = current_version
        
        # Get model path untuk versi ini
        model_path = VERSION_MANAGER.get_model_path(current_version)
        
        if model_path.exists():
            with open(model_path, 'rb') as f:
                MODEL = pickle.load(f)
            
            # Log detail
            info = VERSION_MANAGER.get_version_info(current_version)
            logger.info(f"✓ Model loaded successfully")
            logger.info(f"  Version: {current_version}")
            logger.info(f"  Path: {model_path}")
            if info and "metrics" in info:
                logger.info(f"  Accuracy: {info['metrics'].get('accuracy', 'N/A'):.4f}")
        else:
            logger.warning(f"⚠ Model file not found: {model_path}")
            logger.warning(f"  Version {current_version} specified but file missing")
    
    except Exception as e:
        logger.error(f"✗ Model loading failed: {e}")
        import traceback
        traceback.print_exc()


def _initialize_notifier():
    """Initialize Telegram notifier if configured."""
    global NOTIFIER
    try:
        NOTIFIER = TelegramNotifier()
        if NOTIFIER.is_configured():
            logger.info("✓ Telegram notifier initialized")
        else:
            logger.info("ℹ Telegram not configured (set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID)")
    except Exception as e:
        logger.warning(f"⚠ Telegram notifier initialization failed: {e}")


@app.on_event("startup")
async def startup_event():
    """Load model on startup."""
    _load_model()
    _initialize_notifier()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint dengan info versi model."""
    return HealthResponse(
        status="healthy" if MODEL is not None else "unhealthy",
        model_loaded=MODEL is not None,
        model_version=f"{MODEL_VERSION}.0-xgboost" if MODEL_VERSION else "unknown",
    )


@app.post("/predict/single", response_model=PredictionResult)
async def predict_single(log: LogRequest):
    """
    Predict single log entry.
    
    Example:
    POST /predict/single
    {
        "method": "POST",
        "uri": "/index.php/article/submit",
        "user_agent": "Mozilla/5.0...",
        "status": 200
    }
    """
    if MODEL is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded",
        )
    
    try:
        # Convert single log to DataFrame
        df = pd.DataFrame([log.dict(exclude_none=True)])
        
        # Filter to required columns only
        required_cols = [
            "method", "uri", "status", "bytes_sent", "request_time",
            "user_agent", "rule_count", "severity_score"
        ]
        available_cols = [c for c in required_cols if c in df.columns]
        df = df[available_cols]
        
        # Build features
        features_df = build_tabular_features(df)
        
        # Predict
        prob = MODEL.predict_proba(features_df)[0, 1]
        pred = int(MODEL.predict(features_df)[0])
        
        # Determine severity
        if pred == 0:
            severity = "normal"
        elif prob < 0.7:
            severity = "low"
        elif prob < 0.85:
            severity = "medium"
        else:
            severity = "high"
        
        return PredictionResult(
            method=log.method,
            uri=log.uri,
            attack_probability=float(prob),
            prediction=pred,
            confidence=max(prob, 1 - prob),
            severity=severity,
        )
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@app.post("/predict/batch", response_model=PredictionResponse)
async def predict_batch(request: BatchLogRequest):
    """
    Predict batch of log entries.
    
    Example:
    POST /predict/batch
    {
        "logs": [
            {"method": "GET", "uri": "/"},
            {"method": "POST", "uri": "/submit"}
        ],
        "threshold": 0.5
    }
    """
    if MODEL is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded",
        )
    
    try:
        # Convert logs to DataFrame
        logs_data = [log.dict(exclude_none=True) for log in request.logs]
        df = pd.DataFrame(logs_data)
        
        # Filter to required columns
        required_cols = [
            "method", "uri", "status", "bytes_sent", "request_time",
            "user_agent", "rule_count", "severity_score"
        ]
        available_cols = [c for c in required_cols if c in df.columns]
        df = df[available_cols]
        
        # Build features
        features_df = build_tabular_features(df)
        
        # Predict
        probs = MODEL.predict_proba(features_df)[:, 1]
        preds = MODEL.predict(features_df)
        
        # Build results
        results = []
        for i, log in enumerate(request.logs):
            prob = float(probs[i])
            pred = int(preds[i])
            
            # Severity mapping
            if pred == 0:
                severity = "normal"
            elif prob < 0.7:
                severity = "low"
            elif prob < 0.85:
                severity = "medium"
            else:
                severity = "high"
            
            results.append(
                PredictionResult(
                    method=log.method,
                    uri=log.uri,
                    attack_probability=prob,
                    prediction=pred,
                    confidence=max(prob, 1 - prob),
                    severity=severity,
                )
            )
        
        # Summary
        attack_count = sum(1 for r in results if r.prediction == 1)
        normal_count = len(results) - attack_count
        
        return PredictionResponse(
            total_logs=len(results),
            predictions=results,
            summary={
                "normal_count": normal_count,
                "attack_count": attack_count,
                "attack_percentage": (attack_count / len(results) * 100) if results else 0,
            },
        )
    
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@app.post("/alert")
async def send_alert(alert: AlertRequest):
    """
    Send alert via Telegram (if configured).
    
    Example:
    POST /alert
    {
        "title": "Attack Detected",
        "message": "SQLi attempt on /submit",
        "severity": "high",
        "attack_count": 5
    }
    """
    if NOTIFIER is None or not NOTIFIER.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Notifier not configured",
        )
    
    try:
        await NOTIFIER.send_alert(
            title=alert.title,
            message=alert.message,
            severity=alert.severity,
            attack_count=alert.attack_count,
        )
        return {"status": "sent", "message": "Alert sent successfully"}
    except Exception as e:
        logger.error(f"Alert error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@app.get("/admin/versions")
async def get_versions():
    """
    Admin endpoint: Get semua versions yang pernah dibuat.
    
    Useful untuk:
    - Lihat history training
    - Lihat metric untuk setiap versi
    - Decide mana versi terbaik
    
    Response:
    {
        "current_version": 2,
        "versions": [
            {
                "version": 1,
                "created_at": "2026-04-01T02:00:00",
                "accuracy": 0.995,
                ...
            },
            ...
        ]
    }
    """
    if VERSION_MANAGER is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Version manager not initialized",
        )
    
    return {
        "current_version": VERSION_MANAGER.get_current_version(),
        "versions": VERSION_MANAGER.list_all_versions()
    }


@app.post("/admin/rollback/{version}")
async def rollback_model(version: int):
    """
    Admin endpoint: Rollback ke versi lama.
    
    Scenario: Model v3 jelek, mau balik ke v2
    
    POST /admin/rollback/2
    
    Response:
    {
        "status": "success",
        "message": "Rolled back to version 2",
        "note": "Please restart API to load the model"
    }
    """
    if VERSION_MANAGER is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Version manager not initialized",
        )
    
    try:
        success = VERSION_MANAGER.rollback_to_version(version)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to rollback to version {version}",
            )
        
        return {
            "status": "success",
            "message": f"Rolled back to version {version}",
            "note": "Please restart API server to load the model"
        }
    
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@app.get("/")
async def root():
    """API documentation redirect."""
    return {
        "message": "OJS Attack Detection API",
        "docs": "/docs",
        "endpoints": {
            "health": "GET /health",
            "predict_single": "POST /predict/single",
            "predict_batch": "POST /predict/batch",
            "send_alert": "POST /alert",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
