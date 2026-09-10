"""Calls ReconX scanners through the MCP tool layer (nexus/mcp_server/server.py).

Uses fastmcp's in-memory transport (Client(mcp) against the FastMCP
object directly, no subprocess) so Phase 0 has no extra process to
manage. A real deployment can point this at a stdio/HTTP MCP client
instead without changing any node above it — the dispatcher is the only
place that knows how tools are physically reached.

Scope is re-checked here, not just once at the scope_gate node, per the
"checked on every tool call" rule: a planner bug or a future hunter agent
must not be able to walk a tool call outside the authorized scope.
"""

from fastmcp import Client

from nexus.graph.nodes.scope_gate import is_in_scope
from nexus.graph.state import AttackSurface, NEXUSState
from nexus.mcp_server.server import mcp

# NEXUS modes map onto ReconX's existing nmap profiles.
MODE_TO_NMAP_PROFILE = {
    "fast": "fast",
    "standard": "default",
    "deep": "deep",
    "ctf": "deep",
    "bugbounty": "default",
}


def _merge_nmap_results(surface: AttackSurface, nmap_results) -> AttackSurface:
    if not isinstance(nmap_results, list):
        return surface

    hosts = list(surface.hosts)
    open_ports = dict(surface.open_ports)

    for host_entry in nmap_results:
        ip = host_entry.get("ip")
        if not ip:
            continue
        if ip not in hosts:
            hosts.append(ip)
        ports = [
            int(p["portid"])
            for p in host_entry.get("ports", [])
            if p.get("state") == "open" and str(p.get("portid", "")).isdigit()
        ]
        open_ports[ip] = sorted(set(open_ports.get(ip, [])) | set(ports))

    return surface.model_copy(update={"hosts": hosts, "open_ports": open_ports})


async def recon_dispatcher_node(state: NEXUSState) -> dict:
    if not state.active_hunters:
        return {}

    if not is_in_scope(state.target, state.scope):
        return {
            "stop_reason": (
                f"SCOPE VIOLATION at dispatch time: target '{state.target}' is not "
                f"within authorized scope {state.scope}. Aborting."
            ),
            "active_hunters": [],
        }

    surface = state.attack_surface or AttackSurface()
    statuses = dict(state.agent_statuses)
    hunter_results: list[dict] = []

    profile = MODE_TO_NMAP_PROFILE.get(state.mode, "fast")

    async with Client(mcp) as client:
        for hunter in state.active_hunters:
            if hunter == "nmap":
                result = await client.call_tool(
                    "run_nmap",
                    {
                        "target": state.target,
                        "output_dir": state.output_dir,
                        "profile": profile,
                    },
                )
                payload = result.data if hasattr(result, "data") else result
                hunter_results.append(payload)
                surface = _merge_nmap_results(surface, payload.get("results"))
                statuses["nmap"] = "complete"
            else:
                statuses[hunter] = "skipped: no dispatcher wiring yet (Phase 1+)"

    return {
        "active_hunters": [],
        "attack_surface": surface,
        "agent_statuses": statuses,
        "hunter_results": hunter_results,
        "recon_rounds": state.recon_rounds + 1,
    }
