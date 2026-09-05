"""LangGraph graph wiring for NEXUS.

Full topology:
  START -> scope_gate -> recon_planner <--loop--+
                              |                  |
                    (parallel via Send API):     |
              web_attacker, network_attacker,    |
              auth_breaker, api_fuzzer           |
                              |                  |
                    exploit_verifier --[unverified]-+
                              |
                    [all verified]
                              |
                         risk_scorer
                              |
                            critic
                              |
                         synthesizer
                              |
                             END

Key: recon_planner loops (max 4 rounds) until no new attack surface.
This is the core architectural difference vs. fixed-pipeline scanners.
"""

from langgraph.graph import StateGraph, START, END


def build_nexus_graph():
    """Compile the NEXUS LangGraph graph.
    Full implementation in nexus/graph/build_graph.py
    """
    raise NotImplementedError("Full wiring in nexus/graph/build_graph.py")
