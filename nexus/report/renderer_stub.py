"""Report renderer stub.
Outputs: Rich terminal table, HTML (Jinja2), Markdown, JSON.

Every report includes:
1. Executive Summary (business language, CISO-readable)
2. Findings Table (severity/CVSS/EPSS sorted by priority)
3. Per-finding: description, repro steps, verified PoC, remediation
4. Attack Chain Diagram (Mermaid)
5. Scope Coverage Map (what was tested and why things were skipped)
"""


def generate_mermaid_chain(findings: list) -> str:
    """Build a Mermaid diagram showing how findings chain together."""
    lines = ["graph TD"]
    for i, finding in enumerate(findings):
        node_id = f"F{i}"
        label = str(finding.get("title", "Finding"))[:40]
        severity = finding.get("severity", "info")
        color = {
            "critical": "#ff0000", "high": "#ff6600",
            "medium": "#ffaa00", "low": "#00aa00",
        }.get(severity, "#aaaaaa")
        lines.append(f'    {node_id}["{label}"]')
        lines.append(f"    style {node_id} fill:{color}")
    return "\n".join(lines)
