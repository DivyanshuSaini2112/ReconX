"""Free-tier-first LLM routing.

Not called by anything in Phase 0 (the planner is a deterministic stub —
see nexus/graph/nodes/recon_planner.py). Wired now so Phase 1's real
planner, and later the hunter agents, have a single place to get a model
from instead of each hardcoding a provider/model string.

Reuses reconx.lib.config.get_api_key so the same config.ini (with a
GROQ_API_KEY under [API_KEYS]) that already powers `--ai-summary` also
powers NEXUS.
"""

from langchain_groq import ChatGroq

from reconx.lib.config import get_api_key

# Task -> Groq model. Swap here, not at call sites, as better/cheaper
# free-tier models show up.
TASK_MODEL_MAP = {
    "planner": "deepseek-r1-distill-llama-70b",
    "reasoning": "deepseek-r1-distill-llama-70b",
    "tool_use": "llama-3.3-70b-versatile",
    "parsing": "llama-3.3-70b-versatile",
    "default": "llama-3.3-70b-versatile",
}


def get_llm(task: str = "default", temperature: float = 0.0) -> ChatGroq:
    """Return a configured ChatGroq client for the given task category.

    Raises RuntimeError with an actionable message if no key is configured,
    rather than letting a confusing auth error surface from inside the graph.
    """
    api_key = get_api_key("GROQ_API_KEY")
    if not api_key or api_key == "YOUR_GROQ_API_KEY":
        raise RuntimeError(
            "GROQ_API_KEY not configured. Copy reconx/config.ini.example to "
            "config.ini (project root or reconx/) and set GROQ_API_KEY under [API_KEYS]."
        )

    model = TASK_MODEL_MAP.get(task, TASK_MODEL_MAP["default"])
    return ChatGroq(model=model, api_key=api_key, temperature=temperature)
