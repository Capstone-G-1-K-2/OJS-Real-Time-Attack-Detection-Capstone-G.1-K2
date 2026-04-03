from __future__ import annotations

# Shared detection rules for both dataset parsing and inference feature building.
SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1=1",
    r"and\s+1=1",
    r"sleep\s*\(",
    r"information_schema",
    r"drop\s+table",
]

XSS_PATTERNS = [
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
]

SUSPICIOUS_PATH_PATTERNS = [
    r"/wp-admin",
    r"/phpmyadmin",
    r"/etc/passwd",
    r"/\.env",
    r"/admin",
    r"/\.git",
    r"/\.svn",
    r"/\.hg",
    r"/\.bzr",
    r"/node_modules",
    r"/\.aws",
    r"/\.config",
    r"/backup",
    r"/\.bak",
]