from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

import pandas as pd

SQL_KEYWORDS = ["union", "select", "sleep", "drop", "insert", "update", "delete", "or 1=1"]
XSS_KEYWORDS = ["<script", "javascript:", "onerror=", "onload=", "alert("]
SENSITIVE_PATHS = ["/wp-admin", "/phpmyadmin", "/.env", "/etc/passwd", "wp-config.php"]

SPECIAL_CHARS_RE = re.compile(r"[^a-zA-Z0-9]")
DIGIT_RE = re.compile(r"\d")
HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")


def _safe_str(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _count_keywords(text: str, keywords: list[str]) -> int:
    lowered = text.lower()
    return sum(1 for kw in keywords if kw in lowered)


def build_tabular_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build tabular features from parsed HTTP log rows.

    This intentionally avoids leakage-prone columns from response/audit outcomes,
    such as HTTP status, ModSecurity rule count, and severity-derived signals.
    """
    if "uri" not in df.columns:
        raise ValueError("Kolom 'uri' wajib ada untuk ekstraksi fitur tabular.")

    uri = df["uri"].map(_safe_str)
    method = df["method"].map(_safe_str).str.upper() if "method" in df.columns else pd.Series("GET", index=df.index)
    user_agent = df["user_agent"].map(_safe_str) if "user_agent" in df.columns else pd.Series("", index=df.index)

    parsed = uri.map(urlparse)
    path = parsed.map(lambda x: x.path or "")
    query = parsed.map(lambda x: x.query or "")

    # Basic lexical features from request intent.
    features = pd.DataFrame(index=df.index)
    features["method"] = method
    features["uri_length"] = uri.str.len()
    features["path_length"] = path.str.len()
    features["query_length"] = query.str.len()
    features["num_query_params"] = query.map(lambda q: len(parse_qs(q)))
    features["num_slashes"] = uri.str.count("/")
    features["num_dots"] = uri.str.count(r"\.")
    features["num_special_chars"] = uri.map(lambda s: len(SPECIAL_CHARS_RE.findall(s)))
    features["num_digits"] = uri.map(lambda s: len(DIGIT_RE.findall(s)))
    features["num_hex_encoded"] = uri.map(lambda s: len(HEX_RE.findall(s)))

    full_text = (uri + " " + user_agent.map(_safe_str)).str.lower()
    features["sql_keyword_hits"] = full_text.map(lambda s: _count_keywords(s, SQL_KEYWORDS))
    features["xss_keyword_hits"] = full_text.map(lambda s: _count_keywords(s, XSS_KEYWORDS))
    features["has_sensitive_path"] = path.str.lower().map(lambda s: int(any(p in s for p in SENSITIVE_PATHS)))
    features["has_query"] = query.map(lambda s: int(len(s) > 0))

    return features
