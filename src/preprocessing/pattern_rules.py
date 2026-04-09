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

# Path Traversal patterns - detect directory traversal attempts
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",  # ../
    r"\.\.\\",  # ..\ (Windows)
    r"%2e%2e/",  # URL encoded ../
    r"%2e%2e\\",  # URL encoded ..\
    r"\.\.%2f",  # URL encoded ../
    r"/etc/",
    r"/proc/",
    r"/sys/",
    r"/root/",
    r"c:\\windows",
    r"c:\\winnt",
]

# Command Injection patterns - detect shell metacharacters and commands
COMMAND_INJECTION_PATTERNS = [
    r";\s*cat\s+",
    r";\s*ls\s+",
    r";\s*whoami",
    r";\s*id\s+",
    r";\s*uname\s+",
    r"\$\(",  # $(command)
    r"`[^`]+`",  # `command`
    r"\|\s*nc\s+",  # pipe to netcat
    r"\|\s*bash",  # pipe to bash
    r"&\s*cat\s+",  # & cat
    r">\s*/dev/null",  # redirect to /dev/null (cleanup)
]