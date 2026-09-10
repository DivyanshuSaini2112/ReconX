"""The planner ("the brain") that decides what runs next.

Phase 0 is a deterministic stub on purpose: round 1 dispatches nmap,
round 2 stops. This is the exact Phase 0 milestone from the ReconX Agent
build roadmap. Swapping this for a real LLM-driven planner (reading
state.attack_surface and reasoning about next hunters/tools) is Phase 1
work — see nexus/gateway/llm_router.py, which is already wired for that.
"""

from nexus.graph.state import NEXUSState

MAX_PLANNER_ROUNDS = 4


def recon_planner_node(state: NEXUSState) -> dict:
    if state.stop_reason:
        return {}

    if state.planner_round >= MAX_PLANNER_ROUNDS:
        return {
            "stop_reason": "max_planner_rounds_reached",
            "active_hunters": [],
        }

    if state.planner_round == 0:
        return {
            "planner_round": state.planner_round + 1,
            "active_hunters": ["nmap"],
            "agent_statuses": {
                **state.agent_statuses,
                "recon_planner": (
                    "round 1: dispatching nmap "
                    "(stub planner — LLM reasoning lands in Phase 1)"
                ),
            },
        }

    return {
        "planner_round": state.planner_round + 1,
        "stop_reason": "phase0_stub_complete: recon baseline gathered, no further hunters wired yet",
        "active_hunters": [],
    }


def route_after_planner(state: NEXUSState) -> str:
    return "dispatch" if state.active_hunters else "end"
