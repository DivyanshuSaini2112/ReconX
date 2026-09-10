"""NVD CVE lookup client. Free API, no key required (rate-limited).
Used by network_attacker to map service versions to known CVEs.

Rate limit: 5 req/30s without API key, 50 req/30s with NVD_API_KEY in .env.
"""

import httpx
from typing import Optional

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(keyword: str, max_results: int = 5) -> list:
    """Search NVD for CVEs matching a product/version keyword."""
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    try:
        r = httpx.get(NVD_BASE, params=params, timeout=15)
        data = r.json()
        return [
            {
                "id": v["cve"]["id"],
                "description": v["cve"]["descriptions"][0]["value"],
                "cvss": _extract_cvss(v),
            }
            for v in data.get("vulnerabilities", [])
        ]
    except Exception:
        return []


def _extract_cvss(vuln: dict) -> Optional[float]:
    try:
        metrics = vuln["cve"]["metrics"]
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    except (KeyError, IndexError):
        pass
    return None
