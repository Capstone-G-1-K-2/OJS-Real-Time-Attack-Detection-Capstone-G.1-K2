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
    HOST_HEADER_XSS_PATTERNS,
    CSRF_PATTERNS,
    PRIVESC_PATTERNS,
    EXECUTABLE_EXTENSIONS,
    FILE_UPLOAD_BYPASS_PATTERNS,
    CVE_2023_47271_XML_BODY_PATTERNS,
    CVE_2023_47271_ACCESS_PATTERNS,
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
    
    # ============ CVE-SPECIFIC FEATURES ============
    
    # CVE-2022-24181: XSS via Host Header (looks for XSS in headers/unusual locations)
    host_header = df["host_header"].map(_safe_str) if "host_header" in df.columns else pd.Series("", index=df.index)
    features["has_cve_2022_24181"] = host_header.map(lambda s: _contains_pattern(s, HOST_HEADER_XSS_PATTERNS))
    
    # CVE-2023-6671: CSRF (detect missing/suspicious CSRF tokens)
    features["missing_csrf_token"] = (~full_text.map(lambda s: _contains_pattern(s, CSRF_PATTERNS))).astype(int)
    features["has_suspicious_referer"] = ((df["referer"].map(_safe_str) if "referer" in df.columns else pd.Series("", index=df.index)) == "-").astype(int)
    
    # CVE-2024-25434/36/38: XSS + Privilege Escalation
    features["has_cve_2024_xss_privesc"] = full_text.map(
        lambda s: _contains_pattern(s, XSS_PATTERNS) * _contains_pattern(s, PRIVESC_PATTERNS)
    )
    features["has_privesc_attempt"] = full_text.map(lambda s: _contains_pattern(s, PRIVESC_PATTERNS))
    
    # CVE-2021-32626: RCE via arbitrary file upload
    features["has_executable_upload"] = uri_decoded.map(lambda s: _contains_pattern(s, EXECUTABLE_EXTENSIONS))
    features["has_file_upload_bypass"] = uri_decoded.map(lambda s: _contains_pattern(s, FILE_UPLOAD_BYPASS_PATTERNS))
    features["has_cve_2021_32626"] = (
        features["has_executable_upload"] | features["has_file_upload_bypass"]
    ).astype(int)

    # CVE-2023-47271: Arbitrary PHP-like File Upload via Native XML Import
    features["has_cve_2023_47271_upload"] = full_text.str.replace('/index.php', '', case=False).str.replace('index.php', '', case=False).map(
        lambda s: _contains_pattern(s, CVE_2023_47271_XML_BODY_PATTERNS)
    ).astype(int)
    features["has_cve_2023_47271_rce"] = uri_decoded.map(
        lambda s: _contains_pattern(s, CVE_2023_47271_ACCESS_PATTERNS)
    ).astype(int)

    return features
