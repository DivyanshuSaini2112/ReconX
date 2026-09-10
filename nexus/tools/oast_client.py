"""OAST client wrapping projectdiscovery/interactsh for blind vulnerability verification.
Used by exploit_verifier to confirm SSRF, blind SQLi, XXE via out-of-band callbacks.
"""

INTERACTSH_DEFAULT = "oast.pro"


def generate_token(finding_id: str) -> str:
    """Generate a unique subdomain token for this finding.
    The verifier polls for callbacks to this token to confirm blind vulns.
    """
    import hashlib
    import os
    nonce = os.urandom(8).hex()
    return hashlib.sha256(f"{finding_id}-{nonce}".encode()).hexdigest()[:16]
