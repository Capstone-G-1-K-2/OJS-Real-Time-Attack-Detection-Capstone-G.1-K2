"""
Parser untuk ModSecurity audit JSON format.

Format: Each line adalah JSON object berisi transaction data.
Support untuk: JSONL (JSON Lines) dan regular JSON array.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

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


def _severity_to_score(severity: str) -> int:
    """Convert severity string to numeric score.
    
    Handles both:
    - Text format: 'EMERGENCY', 'CRITICAL', 'ERROR', etc.
    - Numeric format: '0', '1', '2', '3', '4', '5'
    """
    if not severity:
        return 0
    
    severity_str = str(severity).strip().upper()
    
    # Try numeric first (ModSecurity uses 0-5)
    try:
        numeric_val = int(severity_str)
        return min(max(numeric_val, 0), 5)  # Clamp to 0-5 range
    except ValueError:
        pass
    
    # Try text mapping
    text_mapping = {
        "EMERGENCY": 5,
        "ALERT": 5,
        "CRITICAL": 4,
        "ERROR": 3,
        "WARNING": 2,
        "NOTICE": 1,
        "INFO": 0,
        "DEBUG": 0,
    }
    return text_mapping.get(severity_str, 0)


def _contains_pattern(text: str, patterns: list[str]) -> int:
    """Check if any pattern matches in text (regex-based)."""
    if not text:
        return 0
    for pattern in patterns:
        try:
            if re.search(pattern, text, flags=re.IGNORECASE):
                return 1
        except re.error:
            continue
    return 0


def _extract_from_json_transaction(tx: dict[str, Any]) -> dict[str, Any]:
    """Extract features dari satu JSON transaction object.
    
    Args:
        tx: Transaction dictionary dari JSON
        
    Returns:
        Dictionary dengan extracted features
    """
    
    # Default values
    row = {
        "timestamp": "",
        "source_ip": "0.0.0.0",
        "method": "GET",
        "uri": "/",
        "status": 200,
        "bytes_sent": 0,
        "request_time": 0.0,
        "user_agent": "",
        "user_agent_len": 0,
        "uri_len": 0,
        "severity": "INFO",
        "severity_score": 0,
        "rule_id": "",
        "matched_data": "",
        "msg": "",
        "is_blocked": False,
        "rule_count": 0,
        "has_sqli": 0,
        "has_xss": 0,
        "has_suspicious_path": 0,
        "has_path_traversal": 0,
        "has_command_injection": 0,
        "has_cve_2022_24181": 0,
        "missing_csrf_token": 0,
        "has_suspicious_referer": 0,
        "has_cve_2024_xss_privesc": 0,
        "has_privesc_attempt": 0,
        "has_cve_2021_32626": 0,
        "has_cve_2023_47271_upload": 0,
        "has_cve_2023_47271_rce": 0,
        "label": 0,
    }
    
    try:
        # Extract timestamp
        row["timestamp"] = tx.get("time_stamp", "")
        
        # Extract IPs
        row["source_ip"] = tx.get("client_ip", "0.0.0.0")
        
        # Extract request info
        request = tx.get("request", {})
        if isinstance(request, dict):
            row["method"] = request.get("method", "GET")
            row["uri"] = request.get("uri", "/")
            
            # Extract User-Agent from headers
            headers = request.get("headers", {})
            if isinstance(headers, dict):
                row["user_agent"] = headers.get("User-Agent", "")
        
        # Extract response info
        response = tx.get("response", {})
        if isinstance(response, dict):
            row["status"] = response.get("http_code", 200)
            
            # Get response body length
            body = response.get("body", "")
            if isinstance(body, str):
                row["bytes_sent"] = len(body)
        
        # Extract messages and check if blocked
        messages = tx.get("messages", [])
        row["rule_count"] = len(messages)  # COUNT of triggered rules
        
        if isinstance(messages, list) and len(messages) > 0:
            # Flag sebagai attack jika ada messages
            row["label"] = 1
            row["is_blocked"] = True
            
            # Aggregate info dari semua messages
            all_msgs = []
            all_data = []
            max_severity_score = 0
            max_rule_id = ""
            
            for msg_obj in messages:
                if isinstance(msg_obj, dict):
                    message_text = msg_obj.get("message", "")
                    all_msgs.append(message_text)
                    
                    details = msg_obj.get("details", {})
                    if isinstance(details, dict):
                        rule_id = details.get("ruleId", "")
                        if rule_id:
                            max_rule_id = rule_id
                        
                        severity = details.get("severity", "")
                        severity_score = _severity_to_score(severity)
                        if severity_score > max_severity_score:
                            max_severity_score = severity_score
                            row["severity"] = severity or "INFO"
                        
                        data = details.get("data", "")
                        if data:
                            all_data.append(data)
            
            row["msg"] = " | ".join(all_msgs)
            row["matched_data"] = " | ".join(all_data)
            row["rule_id"] = max_rule_id
            row["severity_score"] = max_severity_score
        
        # Calculate lengths
        row["user_agent_len"] = len(row["user_agent"])
        row["uri_len"] = len(row["uri"])
        
        # Extract pattern features
        full_text = f"{row['uri']} {row['msg']} {row['matched_data']}"
        
        row["has_sqli"] = _contains_pattern(full_text, SQLI_PATTERNS)
        row["has_xss"] = _contains_pattern(full_text, XSS_PATTERNS)
        row["has_suspicious_path"] = _contains_pattern(row["uri"], SUSPICIOUS_PATH_PATTERNS)
        row["has_path_traversal"] = _contains_pattern(row["uri"], PATH_TRAVERSAL_PATTERNS)
        row["has_command_injection"] = _contains_pattern(row["uri"], COMMAND_INJECTION_PATTERNS)
        
        # ============ CVE-SPECIFIC FEATURES ============
        
        # CVE-2022-24181: XSS via Host Header
        host_header = request.get("headers", {}).get("Host", "")
        row["has_cve_2022_24181"] = _contains_pattern(host_header, HOST_HEADER_XSS_PATTERNS)
        
        # CVE-2023-6671: CSRF (detect missing CSRF tokens in POST requests)
        # Only flag as missing if: POST request AND no CSRF pattern found
        is_post = row["method"].upper() == "POST"
        has_csrf_pattern = _contains_pattern(full_text, CSRF_PATTERNS)
        row["missing_csrf_token"] = 1 if (is_post and not has_csrf_pattern) else 0
        
        # Suspicious Referer (only for POST requests - GET requests usually lack Referer)
        referer = request.get("headers", {}).get("Referer", "")
        row["has_suspicious_referer"] = 1 if (is_post and (not referer or referer == "-")) else 0
        
        # CVE-2024-25434/36/38: XSS + Privilege Escalation
        has_xss = _contains_pattern(full_text, XSS_PATTERNS)
        has_privesc = _contains_pattern(full_text, PRIVESC_PATTERNS)
        row["has_cve_2024_xss_privesc"] = 1 if (has_xss and has_privesc) else 0
        row["has_privesc_attempt"] = has_privesc
        
        # CVE-2021-32626: RCE via arbitrary file upload
        has_exec = _contains_pattern(row["uri"], EXECUTABLE_EXTENSIONS)
        has_bypass = _contains_pattern(row["uri"], FILE_UPLOAD_BYPASS_PATTERNS)
        row["has_cve_2021_32626"] = 1 if (has_exec or has_bypass) else 0

        # CVE-2023-47271: XML Body File Upload & Access
        # We assume the request body might be logged in matched_data or msg if it triggered the modsec rule
        # or we check the full_text.
        row["has_cve_2023_47271_upload"] = _contains_pattern(full_text, CVE_2023_47271_XML_BODY_PATTERNS)
        row["has_cve_2023_47271_rce"] = _contains_pattern(row["uri"], CVE_2023_47271_ACCESS_PATTERNS)
        
    except Exception as e:
        print(f"[WARN] Error extracting transaction: {e}")
    
    return row


def parse_modsecurity_json(file_path: str | Path) -> pd.DataFrame:
    """Parse ModSecurity JSON audit log format.
    
    Support untuk:
    - JSONL format (satu JSON object per line)
    - Regular JSON array format
    
    Args:
        file_path: Path ke JSON log file
        
    Returns:
        pd.DataFrame with extracted features and label
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    rows = []
    
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        content = f.read().strip()
    
    # Try JSONL format first (one JSON per line)
    if content.count('\n') > 0 and not content.startswith('['):
        # Likely JSONL format
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                obj = json.loads(line)
                # Handle nested "transaction" key
                tx = obj.get("transaction", obj)
                if isinstance(tx, dict):
                    row = _extract_from_json_transaction(tx)
                    rows.append(row)
            except json.JSONDecodeError as e:
                print(f"[WARN] Failed to parse JSONL line: {e}")
                continue
    else:
        # Try regular JSON array format
        try:
            data = json.loads(content)
            
            if isinstance(data, list):
                # Array of transactions
                for obj in data:
                    tx = obj.get("transaction", obj)
                    if isinstance(tx, dict):
                        row = _extract_from_json_transaction(tx)
                        rows.append(row)
            elif isinstance(data, dict):
                # Single transaction or wrapped format
                tx = data.get("transaction", data)
                if isinstance(tx, dict):
                    row = _extract_from_json_transaction(tx)
                    rows.append(row)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse JSON: {e}")
            raise
    
    df = pd.DataFrame(rows)
    return df


def load_modsec_json_log(log_file_path: str | Path) -> pd.DataFrame:
    """Load ModSecurity JSON log dari file.
    
    Args:
        log_file_path: Path ke JSON log file
        
    Returns:
        pd.DataFrame dengan extracted features and label
    """
    log_file = Path(log_file_path)
    
    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")
    
    print(f"[INFO] Parsing {log_file}...")
    df = parse_modsecurity_json(log_file)
    print(f"[OK] Loaded {len(df)} transactions")
    
    return df
