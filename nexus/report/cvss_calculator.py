"""Local CVSS v3.1 base score calculator.
EPSS scores fetched from api.first.org (free, no auth required).

Final Score = 0.3 * CVSS_Base + 0.4 * EPSS_Percentile + 0.3 * Context_Score
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class CVSSVector:
    attack_vector: str       # N/A/L/P
    attack_complexity: str   # L/H
    privileges_required: str # N/L/H
    user_interaction: str    # N/R
    scope: str               # U/C
    confidentiality: str     # N/L/H
    integrity: str           # N/L/H
    availability: str        # N/L/H

    def base_score(self) -> float:
        """Calculate CVSS v3.1 base score. See FIRST.org spec."""
        raise NotImplementedError


def fetch_epss(cve_id: str) -> Optional[float]:
    """Fetch EPSS probability from FIRST.org API. Returns 0.0 if not found."""
    import httpx
    try:
        r = httpx.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=10
        )
        data = r.json()
        if data.get("data"):
            return float(data["data"][0]["epss"])
    except Exception:
        pass
    return 0.0
