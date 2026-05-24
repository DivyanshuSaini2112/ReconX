"""Auth Breaker Agent stub.
Full implementation tests:
- JWT: alg:none bypass, weak secret brute-force, kid injection
- OAuth: state CSRF, redirect_uri manipulation, token leakage in referrer
- Sessions: fixation, cookie security attributes (HttpOnly, Secure, SameSite)
- Password reset: token predictability, host header injection
- API key detection: regex patterns in JS files and response headers
"""

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "jwt", "key",
    "your-256-bit-secret", "changeme", "supersecret",
]

COOKIE_FLAGS_TO_CHECK = ["HttpOnly", "Secure", "SameSite"]
