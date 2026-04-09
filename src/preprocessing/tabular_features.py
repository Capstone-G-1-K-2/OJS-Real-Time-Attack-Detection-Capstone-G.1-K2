from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, unquote_plus

import pandas as pd

from src.preprocessing.pattern_rules import (
    SQLI_PATTERNS,
    SUSPICIOUS_PATH_PATTERNS,
    XSS_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
)

SPECIAL_CHARS_RE = re.compile(r"[^a-zA-Z0-9]")
DIGIT_RE = re.compile(r"\d")
HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")


def _safe_str(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _contains_pattern(text: str, patterns: list[str]) -> int:
    """Check if any pattern matches in text (regex-based, like modsec_parser)."""
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return 1
    return 0


def build_tabular_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build tabular features from HTTP request data.
    
    Aligns with training features from modsec_parser for consistency.
    Supports both full audit logs and minimal request data (with defaults).
    """
    if "uri" not in df.columns:
        raise ValueError("Kolom 'uri' wajib ada untuk ekstraksi fitur tabular.")

    uri = df["uri"].map(_safe_str)
    # Decode URI untuk catch encoded payloads
    uri_decoded = uri.map(unquote_plus)
    
    method = df["method"].map(_safe_str).str.upper() if "method" in df.columns else pd.Series("GET", index=df.index)
    user_agent = df["user_agent"].map(_safe_str) if "user_agent" in df.columns else pd.Series("", index=df.index)

    # Extract features that match training pipeline
    features = pd.DataFrame(index=df.index)
    
    # Direct fields (with defaults for inference)
    features["method"] = method
    features["uri"] = uri
    features["status"] = df["status"].fillna(200) if "status" in df.columns else 200
    features["bytes_sent"] = df["bytes_sent"].fillna(0) if "bytes_sent" in df.columns else 0
    features["request_time"] = df["request_time"].fillna(0.0) if "request_time" in df.columns else 0.0
    features["rule_count"] = df["rule_count"].fillna(0) if "rule_count" in df.columns else 0
    features["severity_score"] = df["severity_score"].fillna(0) if "severity_score" in df.columns else 0
    features["user_agent_len"] = user_agent.str.len()
    features["uri_len"] = uri.str.len()
    
    # Pattern matching (using decoded URI to catch obfuscated attacks)
    full_text = uri_decoded + " " + user_agent.map(_safe_str)
    features["has_sqli_pattern"] = full_text.map(lambda s: _contains_pattern(s, SQLI_PATTERNS))
    features["has_xss_pattern"] = full_text.map(lambda s: _contains_pattern(s, XSS_PATTERNS))
    features["has_suspicious_path"] = uri.map(lambda s: _contains_pattern(s, SUSPICIOUS_PATH_PATTERNS))
    features["has_path_traversal"] = uri_decoded.map(lambda s: _contains_pattern(s, PATH_TRAVERSAL_PATTERNS))
    features["has_command_injection"] = uri_decoded.map(lambda s: _contains_pattern(s, COMMAND_INJECTION_PATTERNS))

    return features
