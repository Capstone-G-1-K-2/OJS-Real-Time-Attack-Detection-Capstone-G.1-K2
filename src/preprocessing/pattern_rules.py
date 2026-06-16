from __future__ import annotations

# Shared detection rules for both dataset parsing and inference feature building.


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

# CVE-2023-47271: Arbitrary PHP-like File Upload via Native XML Import
CVE_2023_47271_XML_BODY_PATTERNS = [
    r"(?i)([a-z0-9_\-./]+?\.(?:php|phtml|phar|php[0-9]?|pht))\b"
]

CVE_2023_47271_ACCESS_PATTERNS = [
    r"(?i)^/?public/journals/[0-9]+/[^?]+\.(?:php|phtml|phar|php[0-9]?|pht)(?:\?.*)?$"
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