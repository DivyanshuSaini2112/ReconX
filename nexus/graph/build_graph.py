"""Wires the Phase 0 graph:

    scope_gate -> recon_planner -> recon_dispatcher -> recon_planner -> ... -> END

recon_planner is the only node that decides what runs next, and every
loop back through it re-evaluates whether to stop (see MAX_PLANNER_ROUNDS
in nexus/graph/nodes/recon_planner.py). Later phases add hunter/verifier/
scorer/synthesizer nodes off the same recon_planner decision point —
nothing here needs to change shape for that, only the routing table grows.
"""

from langgraph.graph import END, StateGraph

from nexus.graph.nodes.recon_dispatcher import recon_dispatcher_node
from nexus.graph.nodes.recon_planner import recon_planner_node, route_after_planner
from nexus.graph.nodes.scope_gate import route_after_scope_gate, scope_gate_node
from nexus.graph.state import NEXUSState


def build_graph():
    graph = StateGraph(NEXUSState)

    graph.add_node("scope_gate", scope_gate_node)
    graph.add_node("recon_planner", recon_planner_node)
    graph.add_node("recon_dispatcher", recon_dispatcher_node)

    graph.set_entry_point("scope_gate")

    graph.add_conditional_edges(
        "scope_gate",
        route_after_scope_gate,
        {"continue": "recon_planner", "end": END},
    )
    graph.add_conditional_edges(
        "recon_planner",
        route_after_planner,
        {"dispatch": "recon_dispatcher", "end": END},
    )
    graph.add_edge("recon_dispatcher", "recon_planner")

    return graph.compile()
