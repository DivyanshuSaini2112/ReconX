"""ReconX Agent shared state schema (LangGraph state + supporting models).

Phase 0 scope: only the fields actually read/written by scope_gate,
recon_planner, and recon_dispatcher are exercised today. The remaining
fields are declared now so later phases (hunter swarm, verifier, risk
scorer, synthesizer) can extend the same graph without a schema migration.
"""

import operator
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, Field

NexusMode = Literal["fast", "standard", "deep", "ctf", "bugbounty"]


class WebApp(BaseModel):
    url: str
    tech_stack: list[str] = Field(default_factory=list)
    login_detected: bool = False


class AttackSurface(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    web_apps: list[WebApp] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)


class ExploitAttempt(BaseModel):
    finding_id: str
    method: str
    payload: str = ""
    response_snippet: str = ""
    verified: bool = False
    evidence: str = ""


class RiskFinding(BaseModel):
    id: str
    title: str
    severity: str
    description: str = ""
    cvss_base: Optional[float] = None
    epss_percentile: Optional[float] = None
    context_score: Optional[float] = None


class NEXUSState(BaseModel):
    # --- input ---
    target: str
    scope: list[str]
    mode: NexusMode = "fast"
    output_dir: str

    # --- control / safety ---
    consent_confirmed: bool = False
    scope_violations: int = 0
    stop_reason: Optional[str] = None

    # --- phase 1: recon ---
    attack_surface: Optional[AttackSurface] = None
    recon_rounds: int = 0

    # --- phase 2: hunter swarm ---
    active_hunters: list[str] = Field(default_factory=list)
    hunter_results: Annotated[list[dict], operator.add] = Field(default_factory=list)

    # --- phase 3: verification ---
    exploit_attempts: Annotated[list[ExploitAttempt], operator.add] = Field(default_factory=list)

    # --- phase 4: risk scoring ---
    findings: Annotated[list[RiskFinding], operator.add] = Field(default_factory=list)
    critic_notes: list[str] = Field(default_factory=list)

    # --- phase 5: reporting ---
    final_report: Optional[dict] = None

    # --- orchestration bookkeeping ---
    planner_round: int = 0
    agent_statuses: dict[str, str] = Field(default_factory=dict)
    hitl_pending: bool = False
