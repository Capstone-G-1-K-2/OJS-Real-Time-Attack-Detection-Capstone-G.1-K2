"""
Example: How to apply different thresholds for different endpoints
"""

import pickle
import pandas as pd
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def get_threshold_for_endpoint(uri: str) -> float:
    """Return appropriate threshold based on endpoint sensitivity."""
    
    ENDPOINT_THRESHOLDS = {
        "/admin":              0.3,  # Max security
        "/user/register":      0.5,  # Balanced
        "/api/":               0.4,  # Security-focused
        "/search":             0.6,  # Minimize false alarms
        "/article/view":       0.7,  # Very permissive (public)
    }
    
    for endpoint, threshold in ENDPOINT_THRESHOLDS.items():
        if endpoint in uri:
            return threshold
    
    return 0.5  # Default


def predict_with_threshold(model, features, threshold: float = None) -> dict:
    """Make prediction with optional custom threshold."""
    
    if threshold is None:
        threshold = 0.5
    
    # Get probabilities
    probs = model.predict_proba(features)[0]
    attack_prob = probs[1]
    
    # Apply threshold
    is_attack = attack_prob >= threshold
    
    return {
        "is_attack": bool(is_attack),
        "attack_probability": float(attack_prob),
        "threshold_used": float(threshold),
        "confidence": float(max(probs)),
    }


# Example usage
if __name__ == "__main__":
    # Load model
    with open("models/trained_models/modsec_xgb.pkl", 'rb') as f:
        model = pickle.load(f)
    
    # Example requests
    test_requests = [
        {
            "uri": "/index.php/ojs-security/admin/settings",
            "method": "POST",
            "status": 403,
            "bytes_sent": 0,
            "request_time": 0.01,
            "user_agent_len": 50,
            "uri_len": 35,
            "severity_score": 7,
            "rule_id": 942100,
            "has_sqli_pattern": 1,
            "has_xss_pattern": 0,
            "has_suspicious_path": 0,
            "has_path_traversal": 0,
            "has_command_injection": 0,
            "rule_count": 0,
        },
        {
            "uri": "/index.php/ojs-security/search?q=article",
            "method": "GET",
            "status": 200,
            "bytes_sent": 2048,
            "request_time": 0.15,
            "user_agent_len": 100,
            "uri_len": 45,
            "severity_score": 0,
            "rule_id": 0,
            "has_sqli_pattern": 0,
            "has_xss_pattern": 0,
            "has_suspicious_path": 0,
            "has_path_traversal": 0,
            "has_command_injection": 0,
            "rule_count": 0,
        }
    ]
    
    print("=" * 70)
    print("EXAMPLE: DYNAMIC THRESHOLD BY ENDPOINT")
    print("=" * 70)
    print()
    
    for req in test_requests:
        uri = req["uri"]
        
        # Get appropriate threshold for this endpoint
        threshold = get_threshold_for_endpoint(uri)
        
        # Create feature dataframe
        df_req = pd.DataFrame([req])
        
        # Predict with endpoint-specific threshold
        result = predict_with_threshold(model, df_req, threshold)
        
        print(f"Request: {uri}")
        print(f"  Threshold for endpoint: {threshold}")
        print(f"  Attack probability: {result['attack_probability']:.2%}")
        print(f"  Decision: {'BLOCK' if result['is_attack'] else 'ALLOW'}")
        print()
