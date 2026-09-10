"""Bug Bounty mode configuration and behavior overrides.

Key differences from standard mode:
1. Subdomain-first: fully enumerate scope before touching any web surface
2. Rate-conscious: 1-5s random delays, detect 429/Cloudflare and back off
3. Duplicate avoidance: check long-term memory before reporting
4. Business logic testing: semantic checks pure fuzzers miss
5. High-value target prioritization by bug bounty value score
"""

import random
import time

BB_SCORE_WEIGHTS = {
    "auth_bypass_potential": 3,
    "data_access_potential": 2,
    "known_tech_vuln_risk": 1,
}

HIGH_VALUE_SIGNALS = [
    "admin", "login", "dashboard", "api", "graphql",
    "upload", "webhook", "callback", "oauth", "sso",
    "reset", "forgot", ".git", ".env", "backup",
]


def rate_limited_request(func):
    """Decorator: add random delay between requests in bug bounty mode."""
    def wrapper(*args, **kwargs):
        time.sleep(random.uniform(1.0, 5.0))
        return func(*args, **kwargs)
    return wrapper
