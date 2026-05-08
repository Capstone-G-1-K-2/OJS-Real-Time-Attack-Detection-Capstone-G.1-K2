"""Pydantic models for API requests/responses (generic, OJS-agnostic)."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class LogRequest(BaseModel):
    """Single HTTP log entry for prediction."""
    
    method: str = Field(..., example="POST")
    uri: str = Field(..., example="/index.php/article/submit")
    status: Optional[int] = Field(default=200, example=200)
    bytes_sent: Optional[int] = Field(default=0, example=1024)
    request_time: Optional[float] = Field(default=0.0, example=0.123)
    user_agent: Optional[str] = Field(default="", example="Mozilla/5.0...")
    
    # ModSecurity-specific (optional, for audit log format)
    rule_count: Optional[int] = Field(default=0, example=0)
    severity_score: Optional[float] = Field(default=0.0, example=0.0)
    raw_log: Optional[str] = Field(default="", example="Raw audit log text...")
    
    # Metadata
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = Field(default="", example="192.168.1.100")


class BatchLogRequest(BaseModel):
    """Batch of HTTP logs for prediction."""
    
    logs: list[LogRequest] = Field(..., min_items=1)
    threshold: Optional[float] = Field(default=0.5, ge=0.0, le=1.0)


class PredictionResult(BaseModel):
    """Single prediction result."""
    
    method: str
    uri: str
    attack_probability: float
    prediction: int  # 0=normal, 1=attack
    confidence: float
    severity: Optional[str] = None  # "low", "medium", "high"


class PredictionResponse(BaseModel):
    """Response with prediction results."""
    
    total_logs: int
    predictions: list[PredictionResult]
    summary: dict = {
        "normal_count": int,
        "attack_count": int,
        "attack_percentage": float,
    }


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str
    model_loaded: bool
    model_version: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AlertRequest(BaseModel):
    """Request to send alert."""
    
    title: str
    message: str
    severity: str = Field(default="medium")  # "low", "medium", "high", "critical"
    attack_count: int
    logs: Optional[list[dict]] = None
