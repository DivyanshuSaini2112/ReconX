"""Hard engineering control for scope enforcement.

This is deliberately NOT a prompt instruction the planner LLM could be
talked out of. `is_in_scope` is plain Python, called both as a graph node
(before any recon starts) and again inside every hunter/dispatcher node
before it is allowed to call a tool against a target.
"""

import ipaddress

from nexus.graph.state import NEXUSState

MAX_SCOPE_VIOLATIONS = 3


def _extract_host(target: str) -> str:
    host = target
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0]
    return host.strip()


def _entry_matches(host: str, entry: str) -> bool:
    entry = entry.strip()
    if not entry:
        return False

    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        network = None

    if network is not None:
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False

    host_l = host.lower().rstrip(".")
    entry_l = entry.lower().rstrip(".")
    return host_l == entry_l or host_l.endswith("." + entry_l)


def is_in_scope(target: str, scope: list[str]) -> bool:
    """True if `target` (IP, CIDR member, domain, or subdomain) is covered by `scope`."""
    if not scope:
        return False
    host = _extract_host(target)
    return any(_entry_matches(host, entry) for entry in scope)


def scope_gate_node(state: NEXUSState) -> dict:
    if not state.consent_confirmed:
        return {
            "stop_reason": (
                "CONSENT NOT CONFIRMED: authorization must be confirmed at the CLI "
                "before the graph runs. Aborting."
            )
        }

    if not is_in_scope(state.target, state.scope):
        violations = state.scope_violations + 1
        return {
            "scope_violations": violations,
            "stop_reason": (
                f"SCOPE VIOLATION: target '{state.target}' is not within authorized "
                f"scope {state.scope}. Aborting."
            ),
        }

    return {}


def route_after_scope_gate(state: NEXUSState) -> str:
    return "end" if state.stop_reason else "continue"
