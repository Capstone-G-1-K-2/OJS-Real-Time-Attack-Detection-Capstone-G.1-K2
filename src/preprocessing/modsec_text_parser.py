"""
Parser untuk ModSecurity audit text format (non-JSONL).

Format: Transaction blocks separated by --{hash}-{section}--
Sections: A (timestamp), B (request), F (response), H (audit), Z (end)
"""

from __future__ import annotations

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
)


def _extract_timestamp(line: str) -> str:
    """Extract timestamp from A section line."""
    # Format: [02/Aug/2025:00:02:35 +0200]
    match = re.search(r'\[([^\]]+)\]', line)
    return match.group(1) if match else ""


def _extract_request_line(request_section: str) -> dict[str, str]:
    """Extract method, uri, version from request line."""
    lines = request_section.strip().split('\n')
    if not lines:
        return {"method": "GET", "uri": "/", "version": "HTTP/1.1"}
    
    # First line: METHOD URI HTTP/VERSION
    first_line = lines[0].strip()
    parts = first_line.split()
    
    if len(parts) >= 3:
        return {
            "method": parts[0],
            "uri": parts[1],
            "version": parts[2]
        }
    else:
        return {"method": "GET", "uri": "/", "version": "HTTP/1.1"}


def _extract_headers(section: str) -> dict[str, str]:
    """Extract headers from request/response section."""
    headers = {}
    for line in section.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def _extract_response_code(response_section: str) -> int:
    """Extract HTTP status code from response section."""
    # First line: HTTP/1.1 403 Forbidden
    first_line = response_section.strip().split('\n')[0]
    parts = first_line.split()
    
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            return 200
    return 200


def _extract_modsec_action(audit_section: str) -> bool:
    """Check if request was intercepted (blocked)."""
    # Look for "Action: Intercepted"
    return "Action: Intercepted" in audit_section


def _extract_message_info(audit_section: str) -> dict[str, Any]:
    """Extract message, severity, rule ID dari audit section."""
    info = {
        "severity": "",
        "rule_id": "",
        "msg": "",
        "matched_data": ""
    }
    
    # Extract severity
    severity_match = re.search(r'\[severity\s+"([^"]+)"\]', audit_section)
    if severity_match:
        info["severity"] = severity_match.group(1)
    
    # Extract rule ID
    id_match = re.search(r'\[id\s+"?(\d+)"?\]', audit_section)
    if id_match:
        info["rule_id"] = id_match.group(1)
    
    # Extract message
    msg_match = re.search(r'\[msg\s+"([^"]+)"\]', audit_section)
    if msg_match:
        info["msg"] = msg_match.group(1)
    
    # Extract matched phrase/data
    matched_match = re.search(r'Matched\s+(?:phrase|data)\s+"([^"]+)"', audit_section)
    if matched_match:
        info["matched_data"] = matched_match.group(1)
    
    return info


def _severity_to_score(severity: str) -> int:
    """Convert severity string to numeric score."""
    mapping = {
        "EMERGENCY": 5,
        "ALERT": 5,
        "CRITICAL": 4,
        "ERROR": 3,
        "WARNING": 2,
        "NOTICE": 1,
        "INFO": 0,
        "DEBUG": 0,
    }
    return mapping.get((severity or "").upper(), 0)


def _contains_pattern(text: str, patterns: list[str]) -> int:
    """Check if any pattern matches in text (regex-based)."""
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return 1
    return 0


def parse_modsecurity_text(file_path: str | Path) -> pd.DataFrame:
    """Parse ModSecurity text audit log format.
    
    Parses transactions separated by --{hash}-{section}-- markers.
    Handles A, B, F, H, Z sections.
    Auto-labels based on 'Action: Intercepted'.
    
    Returns:
        pd.DataFrame with extracted features and label
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    rows = []
    
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    
    # Split transactions by hash separators (--{hash}--A--)
    transaction_pattern = r'--([a-f0-9]+)-A--\n(.*?)(?=--[a-f0-9]+-A--|$)'
    transactions = re.finditer(transaction_pattern, content, re.DOTALL)
    
    for tx_match in transactions:
        tx_hash = tx_match.group(1)
        tx_content = tx_match.group(2)
        
        # Split by section markers within transaction
        sections = {}
        section_pattern = r'--' + re.escape(tx_hash) + r'-([ABFHZ])--\n(.*?)(?=--' + re.escape(tx_hash) + r'-([A-Z])|--[a-f0-9]+-A--|$)'
        
        for section_match in re.finditer(section_pattern, tx_content, re.DOTALL):
            section_type = section_match.group(1)
            section_content = section_match.group(2)
            sections[section_type] = section_content
        
        # If no sections found in standard format, skip
        if not sections:
            continue
        
        # Extract A section (timestamp, IPs)
        a_section = sections.get('A', '')
        timestamp = _extract_timestamp(a_section) if a_section else ""
        
        # Parse A line: [timestamp] id source_ip source_port dest_ip dest_port
        a_parts = a_section.strip().split()
        source_ip = a_parts[2] if len(a_parts) > 2 else "0.0.0.0"
        
        # Extract B section (request)
        b_section = sections.get('B', '')
        request_info = _extract_request_line(b_section)
        request_headers = _extract_headers(b_section)
        user_agent = request_headers.get("User-Agent", "")
        
        # Extract F section (response)
        f_section = sections.get('F', '')
        status_code = _extract_response_code(f_section)
        response_headers = _extract_headers(f_section)
        content_length = response_headers.get("Content-Length", "0")
        
        # Extract H section (audit/messages)
        h_section = sections.get('H', '')
        is_blocked = _extract_modsec_action(h_section)
        msg_info = _extract_message_info(h_section)
        
        # Extract pattern features
        uri = request_info.get("uri", "/")
        full_text = f"{uri} {msg_info.get('msg', '')} {msg_info.get('matched_data', '')}"
        
        # Build row
        row = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "method": request_info.get("method", "GET"),
            "uri": uri,
            "status": status_code,
            "bytes_sent": 0,  # Not in text format, use 0 as placeholder
            "request_time": 0.0,  # Extracted from Stopwatch in H section if available
            "user_agent": user_agent,
            "user_agent_len": len(user_agent),
            "uri_len": len(uri),
            "severity": msg_info.get("severity", "INFO"),
            "severity_score": _severity_to_score(msg_info.get("severity", "")),
            "rule_id": msg_info.get("rule_id", ""),
            "matched_data": msg_info.get("matched_data", ""),
            "msg": msg_info.get("msg", ""),
            "is_blocked": is_blocked,
            "has_sqli": _contains_pattern(full_text, SQLI_PATTERNS),
            "has_xss": _contains_pattern(full_text, XSS_PATTERNS),
            "has_suspicious_path": _contains_pattern(uri, SUSPICIOUS_PATH_PATTERNS),
            "has_path_traversal": _contains_pattern(uri, PATH_TRAVERSAL_PATTERNS),
            "has_command_injection": _contains_pattern(uri, COMMAND_INJECTION_PATTERNS),
            "label": 1 if is_blocked else 0,  # Auto-label
        }
        
        rows.append(row)
    
    df = pd.DataFrame(rows)
    
    return df


def load_all_modsec_logs(raw_dir: str | Path) -> pd.DataFrame:
    """Load all ModSecurity logs from subdirectories.
    
    Args:
        raw_dir: Directory containing date folders with modsec_audit.anon.log files
        
    Returns:
        Combined pd.DataFrame from all logs
    """
    raw_dir = Path(raw_dir)
    
    all_dfs = []
    log_files = sorted(raw_dir.glob("*/modsec_audit.anon.log"))
    
    print(f"[INFO] Found {len(log_files)} log files")
    
    for log_file in log_files:
        print(f"[INFO] Parsing {log_file.parent.name}/{log_file.name}...")
        
        try:
            df = parse_modsecurity_text(log_file)
            if df.empty:
                print(f"  [WARN] Empty dataframe")
                continue
            
            all_dfs.append(df)
            print(f"  [OK] Loaded {len(df)} transactions")
        except Exception as e:
            print(f"  [ERROR] {e}")
            continue
    
    if not all_dfs:
        raise ValueError("No logs parsed successfully")
    
    combined = pd.concat(all_dfs, ignore_index=True)
    return combined
