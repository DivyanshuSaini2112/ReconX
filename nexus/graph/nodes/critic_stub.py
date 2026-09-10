"""Critic Agent: second-pass review of all findings before report generation.

What the critic looks for:
1. False positives: "SQLi" that is just an error message, no actual injection
2. Upgrade opportunities: two medium findings that chain to critical
   e.g., Open Redirect + SSRF on same domain = critical chain
3. Missing context: finding marked "no auth required" but recon showed auth exists
4. Severity mismatches: CVSS vs actual exploitability in this environment

Output: critic_notes list + updated severity for upgraded/downgraded findings
"""

CHAIN_PATTERNS = [
    ("open_redirect", "ssrf"),        # redirect to internal SSRF
    ("xss", "csrf"),                   # XSS -> steal CSRF token
    ("path_traversal", "lfi"),         # traversal -> local file include
    ("xxe", "ssrf"),                   # XXE -> SSRF via external entity
    ("idor", "data_breach"),           # IDOR at scale -> mass exposure
    ("sqli", "auth_bypass"),           # SQLi -> login bypass
]
