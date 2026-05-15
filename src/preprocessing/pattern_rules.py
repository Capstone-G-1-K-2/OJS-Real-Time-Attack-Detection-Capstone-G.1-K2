from __future__ import annotations

# Shared detection rules for both dataset parsing and inference feature building.
SQLI_PATTERNS = [
    r"union\s+select",
    r"select\s+.*?\s+from",
    r"insert\s+into",
    r"delete\s+from",
    r"or\s+1\s*=\s*1",
    r"or\s+['\"]1['\"]\s*=\s*['\"]1['\"]?",
    r"and\s+1\s*=\s*1",
    r"sleep\s*\(",
    r"waitfor\s+delay",
    r"benchmark\s*\(",
    r"information_schema",
    r"sysobjects",
    r"group_concat",
    r"drop\s+table",
    r"--\s*$",  # SQL comment at end
    r"/\*.*?\*/"  # SQL inline comment
]

XSS_PATTERNS = [
    r"<script",
    r"</script>",
    r"javascript:",
    r"vbscript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onmouseover\s*=",
    r"alert\s*\(",
    r"prompt\s*\(",
    r"confirm\s*\(",
    r"document\.cookie",
    r"<iframe",
    r"<svg",
    r"<img",
    r"eval\s*\(",
]

SUSPICIOUS_PATH_PATTERNS = [
    r"/wp-admin",
    r"/wp-login",
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
    r"%2e%2e%2f", # Fully encoded ../
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
    r"wget\s+",
    r"curl\s+",
    r"ping\s+-c",
    r"cmd\.exe",
    r"powershell",
]

# ============ CVE-SPECIFIC DETECTION PATTERNS ============

# CVE-2022-24181: XSS via Host Header injection (2.4.8 - 3.3.8)
HOST_HEADER_XSS_PATTERNS = [
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"eval\s*\(",
    r"expression\s*\(",
]

# CVE-2023-6671: CSRF detection patterns (3.3.0.13)
CSRF_PATTERNS = [
    r"csrftoken",
    r"csrf_token",
    r"authenticity_token",
    r"__RequestVerificationToken",
]

# CVE-2024-25434/36/38: XSS + Privilege Escalation patterns (< 3.3.0.17)
PRIVESC_PATTERNS = [
    r"role\s*=\s*admin",
    r"role\s*=\s*manager",
    r"role_id\s*=\s*1",
    r"privilege\s*=\s*admin",
    r"author_to_admin",
    r"escalate",
    r"promote",
]

# CVE-2021-32626: RCE via arbitrary file upload (< 2.3.7)
EXECUTABLE_EXTENSIONS = [
    r"\.php",
    r"\.php3",
    r"\.php4",
    r"\.php5",
    r"\.phtml",
    r"\.jsp",
    r"\.jspx",
    r"\.py",
    r"\.sh",
    r"\.exe",
    r"\.dll",
    r"\.so",
]

FILE_UPLOAD_BYPASS_PATTERNS = [
    r"\.php%00",  # null byte
    r"\.php\.jpg",  # double extension
    r"\.php\.png",
    r"\.php\.gif",
    r"\.php\.txt",
    r"%2ephp",  # URL encoded .php
    r"\.jpg\.php",  # extension confusion
    r"\.gif\.php",
]