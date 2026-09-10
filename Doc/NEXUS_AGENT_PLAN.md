# NEXUS — Autonomous Agentic Penetration Testing System
### Built on ReconX · Shannon/PentestGPT-Level Architecture · Full Technical Design

> **Ethical Preamble:** NEXUS is designed exclusively for authorized penetration testing, CTF competitions, and bug bounty programs where explicit written scope authorization exists. Every automated action must operate within a defined scope boundary. Built-in guardrails enforce this at the agent level.

---

## 0. What We're Building (The One-Paragraph Version)

NEXUS takes a single URL or IP, autonomously executes a full penetration test lifecycle — recon → enumeration → vulnerability discovery → exploitation → post-exploitation analysis → verified PoC generation → professional report — and produces findings at a level competitive with senior bug bounty hunters on Bugcrowd/HackerOne. It can solve HackTheBox / TryHackMe labs without human input. It does not simply run scanners and paste output; it **reasons** about what it finds, forms hypotheses, executes targeted exploit chains, verifies impact, and self-corrects when attacks fail. It sits architecturally between PentestGPT (reasoning framework) and Shannon (execution + verification), improving on both.

---

## 1. State of the Art — What We're Benchmarking Against

### 1.1 PentestGPT (GreyDGL, USENIX Security 2024)
- **Architecture:** Three co-operative modules — Reasoning (strategy), Generation (command synthesis), Parsing (output interpretation) — maintaining a Pentesting Task Tree (PTT).
- **Mode:** Primarily human-in-the-loop; the autonomous v1.0 uses LLM agents to drive CLI tools.
- **Limitation:** PTT is a single flat tree. If an exploit branch fails, backtracking is manual or heuristic. No real exploit verification — it reports "likely vulnerable" rather than proven impact.
- **LLM:** GPT-4 / Claude. Performance degrades significantly on harder HTB "hard" machines.

### 1.2 Shannon (Keygraph, 2025–2026)
- **Architecture:** Multi-agent orchestration via Anthropic Claude Agent SDK + Temporal workflow engine. Source-aware (reads app code). Playwright browser automation for exploit delivery. "No Exploit, No Report" policy.
- **Key differentiator:** Source-code correlation — it traces sinks in code before running dynamic tests, eliminating huge classes of false positives.
- **Limitation:** Primarily DevSecOps/white-box focused. Limited black-box external recon capability. Temporal adds operational complexity for self-hosted deployments.
- **Cost:** Enterprise pricing; not self-hostable at Shannon's level.

### 1.3 XBOW / Astra / HackerOne AI (2025–2026)
- **XBOW:** Validation suite approach — generates exploit attempts, validates them against live-fire targets. Impressive on known vulnerability classes.
- **Limitation across all commercial tools:** They lack the "blank-page" reasoning a human uses when facing an unknown tech stack. They excel on known patterns (SQLi, XSS, SSRF via known sinks) but fail on business logic flaws, chained low-severity findings, and novel attack paths.

### 1.4 NEXUS Positioning
NEXUS aims to bridge these gaps by combining:
- **Black-box external recon** (ReconX's existing tool suite — zero change)
- **Multi-agent cyclic reasoning** (LangGraph, not Temporal — simpler, open-source)
- **Real exploit verification** (browser automation + callback servers, Shannon's "No Exploit, No Report" principle)
- **Memory + learning** (findings persist across scans; the agent improves on repeat targets)
- **Open, self-hostable** (Groq free tier by default; pluggable LLM backend)

---

## 2. Full System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           NEXUS CONTROL PLANE                           │
│                                                                         │
│   CLI / API Input                                                       │
│   (target, scope, mode)                                                 │
│         │                                                               │
│         ▼                                                               │
│   ┌─────────────┐     ┌──────────────────────────────────────────┐     │
│   │  Scope Gate │────▶│         LangGraph Orchestrator           │     │
│   │  (consent + │     │                                          │     │
│   │  boundary   │     │  ┌──────────┐   ┌────────────────────┐  │     │
│   │  enforcer)  │     │  │ Planner  │──▶│  Recon Dispatcher  │  │     │
│   └─────────────┘     │  │  Agent   │◀──│  (MCP tool calls)  │  │     │
│                        │  └────┬─────┘   └────────────────────┘  │     │
│                        │       │                                   │     │
│                        │       ▼                                   │     │
│                        │  ┌───────────────────────────────────┐   │     │
│                        │  │      Vulnerability Hunter Swarm   │   │     │
│                        │  │  ┌──────────┐  ┌──────────────┐  │   │     │
│                        │  │  │ Web      │  │  Network     │  │   │     │
│                        │  │  │ Attacker │  │  Attacker    │  │   │     │
│                        │  │  └──────────┘  └──────────────┘  │   │     │
│                        │  │  ┌──────────┐  ┌──────────────┐  │   │     │
│                        │  │  │ Auth     │  │  API/GraphQL │  │   │     │
│                        │  │  │ Breaker  │  │  Fuzzer      │  │   │     │
│                        │  │  └──────────┘  └──────────────┘  │   │     │
│                        │  └───────────────────────────────────┘   │     │
│                        │       │                                   │     │
│                        │       ▼                                   │     │
│                        │  ┌─────────────────────────────────────┐ │     │
│                        │  │        Exploit Verifier             │ │     │
│                        │  │  (Playwright + OAST + shell)        │ │     │
│                        │  └─────────────────────────────────────┘ │     │
│                        │       │                                   │     │
│                        │       ▼                                   │     │
│                        │  ┌─────────────────────────────────────┐ │     │
│                        │  │  Risk Scorer + Critic               │ │     │
│                        │  │  (CVSS/EPSS + LLM ensemble)         │ │     │
│                        │  └─────────────────────────────────────┘ │     │
│                        │       │                                   │     │
│                        │       ▼                                   │     │
│                        │  ┌─────────────────────────────────────┐ │     │
│                        │  │  Report Synthesizer                 │ │     │
│                        │  │  (PoC + remediation + CVSS)         │ │     │
│                        │  └─────────────────────────────────────┘ │     │
│                        └──────────────────────────────────────────┘     │
│                                                                         │
│   ┌──────────────────────────────────────────────────────────────────┐  │
│   │                      MEMORY LAYER                                │  │
│   │  Short-term: LangGraph State  │  Long-term: ChromaDB + SQLite   │  │
│   └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   ┌──────────────────────────────────────────────────────────────────┐  │
│   │                    TOOL LAYER (MCP Server)                       │  │
│   │  ReconX scanners │ Browser (Playwright) │ Shell │ OAST server   │  │
│   └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The Five-Phase Pentest Lifecycle NEXUS Executes

### Phase 1 — Reconnaissance (ReconX Engine, Unchanged)
> *Goal: Build a complete picture of the attack surface.*

**Tools used:** Nmap, Subfinder/SubdomainScanner, WhatWeb, httpx, URLScan, FFuf, Gobuster (lab mode)

**What the agent does that a scanner doesn't:**
- Interprets port/service combinations (e.g., port 2375 open = Docker API exposed → immediately flags as critical, skips standard web enumeration path)
- Detects technology-specific attack surfaces (e.g., WhatWeb reports Laravel → agent knows to check `.env` exposure, Laravel debug mode, mass assignment)
- Feeds recon output into Phase 2 with annotated hypotheses, not raw data

**Outputs to state:** `AttackSurface` object containing hosts, open ports, web apps, tech stack, subdomains, discovered URLs

---

### Phase 2 — Vulnerability Discovery (Multi-Agent Hunter Swarm)
> *Goal: For each surface in AttackSurface, identify exploitable conditions.*

This is the core innovation over ReconX's current `--ai-summary` bolt-on. Instead of summarizing results after the fact, specialized hunter agents run **during** the attack, making live decisions.

#### 2a. Web Attacker Agent
Targets web applications identified in Phase 1.

**Capabilities:**
- **OWASP Top 10 systematic testing:** Not "run Nuclei with all tags" but a reasoned, ordered sequence:
  1. Authentication surface mapping (login forms, API keys, OAuth flows)
  2. Input discovery (parameters, headers, JSON fields, file uploads)
  3. Injection testing (SQLi, XSS, SSTI, XXE, Command injection) with context-aware payloads
  4. Access control testing (IDOR, path traversal, privilege escalation via parameter tampering)
  5. Business logic (price manipulation, workflow bypass, race conditions)
- **Playwright browser automation:** Can actually log in, fill forms, trigger JS-heavy flows — not just HTTP requests
- **Nuclei with narrowed tags:** Derived from Phase 1's tech detection, not the default broad set
- **Payload adaptation:** If initial XSS payload is blocked, agent tries 5 bypass variants before flagging as not vulnerable

#### 2b. Network Attacker Agent
Targets non-web services found in Phase 1.

**Capabilities:**
- Service-specific exploit lookup (CVE correlation via NVD API / local CVE database)
- Default credential testing for exposed services (FTP, SSH, Redis, MongoDB, Elasticsearch, SMB)
- Configuration exposure checks (Docker API, Kubernetes API, cloud metadata endpoints)
- SSL/TLS analysis (outdated protocols, weak ciphers, certificate mismatches)

#### 2c. Auth Breaker Agent
Focuses specifically on authentication and session management.

**Capabilities:**
- JWT analysis (alg:none, weak secret brute-force, kid injection)
- OAuth flow testing (state parameter CSRF, redirect_uri manipulation, implicit flow token leakage)
- Session fixation, cookie security attribute checks
- Password reset flow analysis (token predictability, host header injection)
- API key detection in JS files, git history (via truffleHog-style pattern matching)

#### 2d. API/GraphQL Fuzzer Agent
Activated when Phase 1 detects API endpoints or GraphQL.

**Capabilities:**
- Schema introspection (GraphQL) → automatic field-level injection testing
- REST API parameter fuzzing with semantic awareness (understands that `user_id` fields are worth IDOR-testing)
- Rate limiting and authentication bypass testing
- SSRF via URL parameters (with OAST callback server to verify blind SSRF)

---

### Phase 3 — Exploit Verification ("No PoC, No Report")
> *Goal: Turn "potentially vulnerable" into "proven exploitable with evidence."*

This is the single biggest capability gap between current ReconX and Shannon-level tools. **NEXUS will not report a finding unless it has verified impact.**

**Verification mechanisms:**

| Finding Type | Verification Method |
|---|---|
| Reflected XSS | Playwright: inject payload, confirm alert/DOM modification in headless browser |
| Stored XSS | Playwright: inject, navigate to display page, confirm execution |
| SQLi (Boolean) | Compare true/false condition responses deterministically |
| SQLi (Time-based) | Confirm >N second delay on sleep payload vs. baseline |
| SQLi (Error-based) | Confirm database error message in response |
| SSRF | OAST server receives callback from target → confirmed |
| Blind SQLi | OAST DNS lookup from target confirms OOB exfiltration |
| Command Injection | OAST callback or deterministic output (`id`, `whoami` in response) |
| IDOR | Confirm access to another user's resource with different auth token |
| Open Redirect | Playwright confirms redirect to attacker-controlled domain |
| XXE | OOB callback or file content in response |
| Path Traversal | `/etc/passwd` content in response (with target permission scope check) |
| Exposed Credential | Attempt authentication — confirm login success as verification |

**OAST Server:** NEXUS runs a lightweight Out-of-Band Application Security Testing server locally (similar to Burp Collaborator) that generates unique per-finding subdomains/tokens and listens for HTTP/DNS callbacks to confirm blind vulnerabilities.

---

### Phase 4 — Risk Scoring & Triage
> *Goal: Prioritize findings by real-world exploitability, not just CVSS score.*

**Scoring model (ensemble):**

```
Final Score = 0.3 × CVSS_Base + 0.4 × EPSS_Percentile + 0.3 × Context_Score
```

- **CVSS_Base:** Standard CVSS v3.1 calculation based on finding characteristics
- **EPSS_Percentile:** Exploit Prediction Scoring System — probability this CVE will be exploited in 30 days (via FIRST.org API; free)
- **Context_Score:** LLM-assigned score based on: target exposure (internet-facing vs. internal), auth requirements, data sensitivity indicators discovered during recon, chaining potential with other findings

**Critic Agent:** A second LLM pass that reviews all findings and specifically looks for:
- False positives (e.g., "SQLi" that's actually just an error message without actual injection)
- Upgrade opportunities (e.g., two medium findings that chain to a critical)
- Missing context (finding marked "no auth required" but recon showed auth exists)

---

### Phase 5 — Report Synthesis
> *Goal: Generate a report indistinguishable from a senior human pentester's deliverable.*

**Report components:**
1. **Executive Summary:** Business-language description of risk, written for a CISO not an engineer
2. **Findings Table:** Severity/CVSS/EPSS/status for each finding, sorted by priority
3. **Per-Finding Detail:**
   - Description with technical depth
   - Step-by-step reproduction steps (written so a developer can reproduce it themselves)
   - Verified PoC (curl command, Playwright script, or screenshot)
   - Impact analysis (data at risk, business impact)
   - Remediation with code-level guidance where possible
4. **Attack Chain Visualization:** Mermaid diagram showing how findings relate/chain
5. **Scope Coverage Map:** What was tested, what was skipped and why

**Output formats:** Rich terminal, HTML, Markdown, JSON (for integration with Jira/Linear bug trackers)

---

## 4. Tech Stack — Every Component Justified

### 4.1 Orchestration — LangGraph (not CrewAI, not AutoGen)
**Why LangGraph:**
- Native support for cyclic graphs — essential for "recon → plan → attack → verify → re-plan" loops
- First-class `Send` API for parallel agent dispatch (agents run simultaneously, not sequentially)
- Built-in state persistence (checkpointing to SQLite) — resume interrupted scans
- Human-in-the-loop (HITL) breakpoints at configurable nodes (e.g., "pause before running SQLMap")
- Active maintenance, LangChain ecosystem, wide adoption

**Why not CrewAI:** Process-based (sequential or hierarchical); no native cyclic flows. Fine for DAG workflows, wrong for adaptive pentest loops.

**Why not AutoGen:** Conversation-based multi-agent; agent communication is chatty and hard to deterministically control. Better for collaborative coding agents than security tools with strict scope boundaries.

### 4.2 LLM Routing — Free-Tier-First Gateway

```
Primary:   Groq / llama-3.3-70b-versatile          → $0 (60 RPM, 6K TPM free)
Secondary: Groq / deepseek-r1-distill-llama-70b    → $0 (reasoning tasks)
Tertiary:  Google AI Studio / Gemini 2.0 Flash     → $0 (2M TPM free)
Premium:   Claude Sonnet 4.5 / GPT-4o              → pay per token (opt-in)
```

**Router logic:**
- Planner/Reasoning tasks → DeepSeek-R1 (thinking model, free tier)
- Tool-use / structured output → Llama-3.3-70b (reliable function calling)
- Long-context analysis (big scan outputs) → Gemini 2.0 Flash (1M context window, free)
- Exploit payload generation → Claude Sonnet (best offensive security reasoning; only paid tier)

**Why NOT train a custom LLM from scratch (addressed directly):**
Training a competitive security LLM requires:
- ~100K+ high-quality pentesting examples (exploit chains, tool outputs, reasoning traces)
- $50K–$500K in GPU compute for fine-tuning a 70B model
- Ongoing RLHF with expert security annotators
- The result would still underperform Claude/GPT-4o on reasoning tasks

**What's realistic and better:** Use the routing above + fine-tune a small 7B model (Mistral or Qwen) on **structured output tasks only** (e.g., "parse this Nmap output into AttackSurface schema"). This costs ~$80–120 on RunPod, improves reliability without replacing big models for reasoning. See §8 for the fine-tuning plan.

### 4.3 Browser Automation — Playwright
- Headless Chromium for XSS verification, form interaction, JS-heavy app traversal
- Intercept network requests (act as a MITM for the browser's own traffic)
- Screenshot capture for PoC evidence
- Python-native: `playwright.async_api` integrates cleanly with asyncio + LangGraph

### 4.4 Tool Layer — MCP Server (FastMCP)
Every ReconX scanner is wrapped as an MCP tool. No scanner logic changes. The MCP server runs as a local process; the LangGraph orchestrator calls tools via MCP protocol.

```
FastMCP tools exposed:
  run_nmap          → NmapScanner.run_scan()        [existing]
  run_subenum       → SubdomainScanner.run_scan()   [existing]
  run_whatweb       → WhatWebScanner.run_scan()     [existing]
  run_httpx         → HttpxScanner.run_scan()       [existing]
  run_dirfuzz       → FfufFuzzer.run_scan()         [existing]
  run_nuclei        → NucleiScanner.run_scan()      [existing]
  run_sqlmap        → SqlmapScanner.run_scan()      [existing]
  run_urlscan       → UrlScanScanner.run_scan()     [existing]
  run_playwright    → PlaywrightAgent.run()          [new]
  run_oast_check    → OASTServer.check_callbacks()  [new]
  run_shell         → ScopedShellExecutor.run()     [new, scope-gated]
```

### 4.5 Memory Architecture

**Short-term (in-graph):** `NEXUSState` Pydantic model in LangGraph state — holds everything for the current scan session. Checkpointed to SQLite automatically.

**Long-term (cross-scan):** ChromaDB vector store + SQLite relational store.
- Findings from past scans indexed for semantic search ("have we seen this type of auth bypass on a Laravel app before?")
- Target profiles: known technology stacks, previously confirmed endpoints
- "Vulnerability playbooks": sequences of actions that successfully exploited a class of vulnerability — the agent retrieves and replays these on similar targets

**Why this matters for HTB/CTF:** The agent learns from solved machines. After solving 10 HTB machines with a `PHP deserialization → RCE → privesc via SUID bash` chain, it recognizes that pattern early on new machines and tests it faster.

### 4.6 OAST Server — Lightweight, Self-Hosted

```python
# nexus/tools/oast_server.py
# ~100 lines. Runs as a side process during scans.
# Generates unique subdomain tokens per finding test.
# Listens on HTTP/DNS for callbacks.
# Findings that trigger a callback are auto-verified.
```

For DNS-based OOB (needed for blind SSRF/XXE/SQLi), uses a free tier of [interactsh](https://github.com/projectdiscovery/interactsh) (ProjectDiscovery's public OAST server) as fallback when local DNS isn't configurable.

### 4.7 Container Isolation — Docker (Optional but Recommended)
- All tool execution runs inside a Docker container
- Prevents scope creep: firewall rules inside container enforce target IP/domain whitelist
- Reproducible environment: same tool versions, same wordlists, same behavior
- Matches PentestGPT's Docker-first design — industry standard for autonomous agents

---

## 5. LangGraph — Detailed Node Design

### 5.1 State Schema

```python
class AttackSurface(BaseModel):
    hosts: list[str]
    open_ports: dict[str, list[int]]          # host -> [ports]
    web_apps: list[WebApp]                     # url, tech_stack, login_detected
    subdomains: list[str]
    api_endpoints: list[str]
    hypotheses: list[str]                      # planner's annotated observations

class ExploitAttempt(BaseModel):
    finding_id: str
    method: str                                # "playwright_xss", "sqlmap_blind", "oast_ssrf"
    payload: str
    response_snippet: str
    verified: bool
    evidence: str                              # screenshot path, OAST token, response diff

class NEXUSState(BaseModel):
    # --- input ---
    target: str
    scope: list[str]                           # IPs/domains in scope
    mode: Literal["fast", "standard", "deep", "ctf", "bugbounty"]
    
    # --- phase 1 ---
    attack_surface: Optional[AttackSurface] = None
    recon_rounds: int = 0
    
    # --- phase 2 ---
    active_hunters: list[str] = []
    hunter_results: Annotated[list[dict], add] = []
    
    # --- phase 3 ---
    exploit_attempts: Annotated[list[ExploitAttempt], add] = []
    
    # --- phase 4 ---
    findings: Annotated[list[RiskFinding], add] = []
    critic_notes: list[str] = []
    
    # --- phase 5 ---
    final_report: Optional[dict] = None
    
    # --- control ---
    planner_round: int = 0                     # max 4 rounds before forced stop
    agent_statuses: dict[str, str] = {}
    hitl_pending: bool = False                 # pause for human review if True
```

### 5.2 Graph Topology

```
START
  │
  ▼
scope_gate ──[rejected]──▶ END
  │
  ▼
recon_planner ◀─────────────────────────────────────────────┐
  │                                                          │
  ├──[web apps found]──▶ web_attacker ──────────────────────┤
  ├──[network services]──▶ network_attacker ────────────────┤
  ├──[auth surfaces]──▶ auth_breaker ───────────────────────┤
  ├──[api/graphql]──▶ api_fuzzer ───────────────────────────┤
  └──[nothing more to enumerate]──▶ exploit_verifier        │
                                         │                   │
                               [unverified findings]─────────┘
                               [all verified]──▶ risk_scorer
                                                    │
                                                  critic
                                                    │
                                               synthesizer
                                                    │
                                                   END
```

**Key structural details:**
- `recon_planner` is the ONLY node that decides what runs next — it's the brain
- Hunter agents run in **parallel** via LangGraph `Send` API
- After hunters report, `exploit_verifier` tries to confirm each tentative finding
- If verification fails OR new attack surface is discovered, loop back to `recon_planner` (max `planner_round < 4`)
- `scope_gate` is checked on EVERY tool call inside hunters — scope violation aborts the current hunter immediately

### 5.3 The Planner — System Prompt (Condensed)

```
You are NEXUS, an autonomous penetration testing orchestrator.
SCOPE: {scope_list}  |  TARGET: {target}  |  MODE: {mode}
CURRENT STATE: recon round {planner_round}/4, attack surface: {summary}

Think step by step:
1. What has been found?  2. What vectors are unexplored?
3. Given the tech stack, what vulnerabilities are most likely?
4. What runs next, and with what arguments?

RULES:
- Never target anything outside SCOPE
- Never run sqlmap unless a parameterized URL was found
- If planner_round == 3, only run confirmatory tasks
- Prioritize findings likely to chain (open redirect + SSRF, XSS + CSRF)

OUTPUT: strict JSON with "reasoning", "next_actions" (hunter/tool/args),
and optional "stop_reason" if nothing more to test.
```

---

## 6. CTF / HackTheBox Mode — Solving Labs Autonomously

The `mode: "ctf"` activates HTB-specific behaviors:

### 6.1 CTF-Specific Additions
- **Foothold-first thinking:** After recon, planner asks "what's the foothold vector?" before anything else
- **Flag detection:** After any RCE/file read, search for `/root/root.txt`, `/home/*/user.txt`, `HTB{...}` / `THM{...}` patterns
- **Post-exploitation pipeline:** 
  1. `sudo -l` (sudo misconfiguration)
  2. `find / -perm -4000 2>/dev/null` (SUID binaries)
  3. `crontab -l && cat /etc/crontab` (cron jobs)
  4. `ss -tlnp` (internal services)
  5. LinPEAS / WinPEAS execution
  6. Check `/opt`, `/srv`, `/usr/local/bin` for custom binaries
- **Knowledge retrieval:** Vector search over HTB writeup knowledge base — if current tech stack matches a solved machine's profile, adapt that exploit chain

### 6.2 Common HTB Exploit Chains NEXUS Handles

| Category | Chain | Detection Signal |
|---|---|---|
| Web RCE | SSTI → RCE (Jinja2/Twig/Smarty) | WhatWeb: Python/Flask/PHP-Symfony |
| Web RCE | File upload bypass → webshell | ffuf: `/upload` endpoint exists |
| Web RCE | Deserialization (PHP/Java) | Java app server headers |
| Web RCE | XXE → SSRF → internal service | XML content-type accepted |
| Foothold | Default credentials | Service version fingerprinted |
| Foothold | CVE (known exploit) | Nmap service version → NVD lookup |
| PrivEsc | SUID binary exploitation | LinPEAS SUID output |
| PrivEsc | sudo misconfiguration | `sudo -l` output |
| PrivEsc | Docker group breakout | Current user in `docker` group |
| PrivEsc | Kernel exploit (last resort) | uname -r → searchsploit lookup |

---

## 7. Bug Bounty Mode — Competitive on Bugcrowd/HackerOne

`mode: "bugbounty"` adaptations:

### 7.1 Subdomain-First Strategy
Before touching any web surface, fully enumerate the scope:
- Subfinder + SubdomainScanner + crt.sh + dnsx + amass passive
- httpx probe all discovered subdomains for live hosts
- Technology fingerprint each live host
- **Prioritize:** Dev/staging environments, admin panels, API subdomains

### 7.2 Rate-Conscious Behavior
- Random delays between requests (1–5 seconds, configurable)
- Detect rate limiting responses (429, Cloudflare challenges) and back off
- Rotate User-Agent strings

### 7.3 High-Value Target Prioritization
Planner ranks discovered targets by "bug bounty value":
```
Score = (auth_bypass_potential × 3) + (data_access_potential × 2) + (known_tech_vuln_risk × 1)
```
High-value signals: admin panels without MFA, API endpoints returning user data, file upload functionality, password reset flows, OAuth integrations, exposed `.git` or `.env` files

### 7.4 Business Logic Testing (LLM-Driven)
The Web Attacker in bug bounty mode performs semantic testing that pure fuzzers miss:
- Price manipulation (negative quantities, coupon stacking, integer overflow)
- Workflow bypass (skip step 2 of checkout by directly POSTing to step 3)
- IDOR via predictable IDs (UUIDs vs. sequential integers)
- Mass assignment (POST additional fields not expected by the server)
- SSRF via webhook/callback URL fields (extremely common, high bounty)

### 7.5 Duplicate Avoidance
Before reporting, check long-term memory:
- Has this exact finding (endpoint + payload class) been seen before?
- Does the bug bounty program's known-issue list mention this?
- Cross-reference with nuclei community templates (if a public template exists, the program has seen it)

---

## 8. Fine-Tuning Plan — The Realistic Custom Model Component

**Target:** A 7B parameter model (Qwen2.5-7B or Mistral-7B) fine-tuned for:
1. Structured output reliability (parsing tool outputs into Pydantic schemas without errors)
2. Security-domain knowledge (CVE descriptions, exploit mechanics, OWASP categories)
3. Reasoning trace quality for pentesting decisions

This is NOT training a full security LLM. It's targeted fine-tuning for specific failure modes.

### 8.1 Dataset Construction

| Source | Type | Size | Cost |
|---|---|---|---|
| Nmap/WhatWeb output → AttackSurface JSON | Synthetic (GPT-4o generated + verified) | ~5K examples | $0 (free tier) |
| Planner decisions from real NEXUS runs | Curated from 50 HTB machine sessions | ~2K examples | Time only |
| HackerOne public disclosures | Real vuln descriptions → structured findings | ~10K examples | Free (public) |
| NVD CVE descriptions → remediation | Real CVE → fix format | ~20K examples | Free (public API) |

**Total: ~37K examples — realistic to build in 4–6 weeks**

### 8.2 Training Setup

```
Base model:  Qwen2.5-7B-Instruct (Apache 2.0 license — commercial use allowed)
Method:      QLoRA (4-bit quantization, rank-16 adapters)
Hardware:    2× A100 80GB on RunPod (~$80–120 total compute cost)
Framework:   Unsloth (4× faster than HuggingFace Trainer, 70% less VRAM)
Duration:    ~6 hours training time
```

### 8.3 Deployment

Fine-tuned model runs via Ollama locally (zero API cost after training). Used for:
- Tool output parsing (high-volume, needs to be fast and cheap)
- Draft vulnerability descriptions (polished by Claude/GPT-4o)

NOT used for: exploit reasoning, payload generation, critical security decisions (big models for those).

---

## 9. Repository Structure

```
ReconX/
├── reconx/                              ← EXISTING: zero changes
│   ├── modules/                         ← EXISTING: zero changes
│   ├── lib/                             ← EXISTING: zero changes
│   └── __main__.py                      ← EXISTING: zero changes
│
├── nexus/                               ← NEW: the full agentic system
│   ├── __init__.py
│   ├── main.py                          ← CLI: nexus -t target.com --mode bugbounty
│   │
│   ├── graph/                           ← LangGraph orchestration
│   │   ├── state.py                     ← NEXUSState, AttackSurface, etc.
│   │   ├── build_graph.py               ← graph wiring + compile
│   │   └── nodes/
│   │       ├── scope_gate.py            ← consent + scope boundary enforcement
│   │       ├── recon_planner.py         ← THE BRAIN: decides everything
│   │       ├── web_attacker.py          ← OWASP Top 10 systematic hunter
│   │       ├── network_attacker.py      ← service/CVE/cred hunter
│   │       ├── auth_breaker.py          ← JWT/OAuth/session hunter
│   │       ├── api_fuzzer.py            ← REST/GraphQL hunter
│   │       ├── exploit_verifier.py      ← "No PoC, No Report" enforcement
│   │       ├── risk_scorer.py           ← CVSS/EPSS/context scoring
│   │       ├── critic.py                ← false-positive filter + chain detector
│   │       └── synthesizer.py           ← report generation
│   │
│   ├── mcp_server/
│   │   └── server.py                    ← FastMCP wrapping all ReconX scanners
│   │
│   ├── tools/
│   │   ├── playwright_agent.py          ← browser automation tool
│   │   ├── oast_server.py               ← blind vuln verification server
│   │   ├── scoped_shell.py              ← scope-gated command execution
│   │   ├── nvd_client.py                ← CVE/EPSS lookup
│   │   └── payload_library.py           ← curated payloads per vuln class
│   │
│   ├── memory/
│   │   ├── short_term.py                ← LangGraph state management
│   │   ├── long_term.py                 ← ChromaDB + SQLite store
│   │   └── playbook_retriever.py        ← pattern matching against past exploits
│   │
│   ├── gateway/
│   │   └── llm_router.py                ← free-tier-first LLM routing
│   │
│   ├── server/
│   │   ├── api.py                       ← FastAPI: REST + WebSocket live view
│   │   └── live_view.html               ← real-time scan progress dashboard
│   │
│   └── report/
│       ├── templates/                   ← Jinja2 HTML report templates
│       ├── renderer.py                  ← Rich + HTML + Markdown + JSON output
│       └── cvss_calculator.py           ← local CVSS v3.1 calculation
│
├── nexus_finetune/                      ← Model fine-tuning (separate concern)
│   ├── dataset/
│   │   ├── build_tool_parsing.py        ← synthetic data generation
│   │   ├── build_planner_examples.py    ← curated planner decisions
│   │   └── build_vuln_descriptions.py   ← HackerOne + NVD preprocessing
│   ├── train.py                         ← Unsloth QLoRA training script
│   └── eval.py                          ← benchmark against base model
│
├── tests/
│   ├── test_scope_gate.py
│   ├── test_mcp_tools.py
│   ├── test_exploit_verifier.py
│   └── test_planner.py
│
├── docker/
│   ├── Dockerfile                       ← Kali-based image with all tools
│   └── docker-compose.yml               ← nexus + oast_server + chromadb
│
├── .env.example
├── requirements.txt
└── README.md
```

---

## 10. Build Roadmap — Phased, Completable in 8–12 Weeks

### Phase 0: Foundation (Week 1–2)
- [ ] `nexus/graph/state.py` — full `NEXUSState` schema
- [ ] `nexus/mcp_server/server.py` — wrap all ReconX scanners as MCP tools
- [ ] `nexus/graph/nodes/scope_gate.py` — consent + IP/domain whitelist
- [ ] Stub planner that returns `["nmap"]` first round, empty second round
- [ ] `nexus/gateway/llm_router.py` — Groq free tier default
- [ ] `nexus/main.py` CLI
- **Milestone:** `python -m nexus.main --target 127.0.0.1 --mode fast` runs nmap via MCP and exits cleanly

### Phase 1: Recon Intelligence (Week 2–3)
- [ ] Real LLM planner with full system prompt
- [ ] `AttackSurface` extraction from nmap/whatweb results
- [ ] Playwright basic tool (`run_playwright` MCP tool)
- [ ] interactsh OAST integration (`run_oast_check`)
- **Milestone:** Planner correctly identifies web app on a DVWA VM, dispatches web_attacker

### Phase 2: Web Attacker (Week 3–5)
- [ ] `web_attacker.py` with OWASP Top 10 ordering
- [ ] Nuclei with tech-stack-narrowed tags
- [ ] Playwright XSS probe + verification
- [ ] SQLi boolean-based detection
- [ ] SSRF probe with OAST callback
- [ ] `exploit_verifier.py`
- **Milestone:** NEXUS finds, verifies, and correctly describes XSS + SQLi on DVWA without human input

### Phase 3: Auth + API Hunters (Week 5–6)
- [ ] `auth_breaker.py` — JWT analysis, cookie security, password reset
- [ ] `api_fuzzer.py` — GraphQL introspection + field injection
- [ ] `nexus/memory/long_term.py` with ChromaDB
- [ ] Playbook retriever
- **Milestone:** Auth Breaker correctly identifies weak JWT secret on a test target

### Phase 4: Network + CTF Mode (Week 6–7)
- [ ] `network_attacker.py` — CVE lookup, default credential testing
- [ ] `scoped_shell.py` — scope-enforced shell execution
- [ ] CTF mode: flag detection, LinPEAS, privesc pipeline
- [ ] Metasploit integration for known CVE exploitation
- **Milestone:** NEXUS solves a retired HTB "Easy" machine zero-to-root without human input

### Phase 5: Risk Scoring + Reporting (Week 7–8)
- [ ] `risk_scorer.py` — CVSS v3.1 + EPSS API
- [ ] `critic.py` — false positive review + exploit chain detection
- [ ] `synthesizer.py` — full report (Rich + HTML + JSON)
- [ ] Attack chain Mermaid diagram generation
- **Milestone:** NEXUS produces a professional pentesting report on a test target

### Phase 6: Bug Bounty Mode + Live View (Week 8–10)
- [ ] Bug bounty mode: subdomain-first, rate limiting, duplicate avoidance
- [ ] Business logic testing patterns
- [ ] FastAPI live view server + WebSocket dashboard
- **Milestone:** Run against an authorized bug bounty scope; compare findings to known issues

### Phase 7: Fine-Tuning (Week 10–12)
- [ ] Build 37K example dataset
- [ ] QLoRA fine-tuning on Qwen2.5-7B (~$100 on RunPod)
- [ ] Evaluate vs. base model on 20 HTB scenarios
- [ ] Deploy via Ollama, integrate as primary parsing model
- **Milestone:** Fine-tuned model handles 95%+ of tool output parsing; big model only for reasoning

---

## 11. Evaluation Framework

### 11.1 HTB Benchmark Suite (CTF Mode)

| Difficulty | Machines | Success Target |
|---|---|---|
| Easy | 10 machines | 8/10 (80%) |
| Medium | 7 machines | 4/7 (57%) |
| Hard | 3 machines | 1/3 (33%) |

"Success" = user flag captured within 2 hours, root flag within 4 hours, no human input.

### 11.2 Bug Bounty Benchmark (Authorized Targets)
- OWASP Juice Shop (self-hosted, all vulns known)
- VulnHub VMs
- DVWA all security levels

Measure: finding count, false positive rate, severity accuracy vs. known vulnerability list.

### 11.3 Key Metrics

| Metric | Target |
|---|---|
| False positive rate (post-critic) | < 10% |
| HTB Easy solve rate | > 80% |
| Cost per scan (Groq free tier) | $0 |
| Cost per scan (premium LLM) | < $2.00 |
| Report generation time | < 30 seconds after scan |

---

## 12. Security, Ethics, and Legal Safeguards

### 12.1 Mandatory Scope Enforcement
- Scope Gate runs at startup AND before every tool call
- Any IP/domain not in scope list → tool call blocked, logged, agent warned
- 3 out-of-scope attempts in one session → automatic abort

### 12.2 Consent Prompt (Unchanged from ReconX)
The existing ReconX consent prompt is preserved verbatim in `nexus/main.py`. Not removable via CLI flags. Logged with timestamp to the output directory.

### 12.3 Invasive Tool Thresholds
- SQLMap: only runs if planner found parameterized URLs AND confirms in reasoning
- Metasploit: only in `ctf` mode OR with explicit `--allow-exploit` flag
- Shell execution: all commands logged; dangerous patterns blocked by `scoped_shell.py`

### 12.4 Rate Limiting by Default
All modes include minimum 2-second delay between web requests. `--aggressive` flag required to reduce this.

---

## 13. Dependencies (New — On Top of Existing ReconX deps)

```
# Orchestration
langgraph>=0.2.0
langchain-core>=0.3.0
langchain-groq>=0.1.0
langchain-anthropic>=0.1.0       # optional, Claude

# Tool layer
fastmcp>=0.9.0
playwright>=1.44.0

# Memory
chromadb>=0.5.0
sqlalchemy>=2.0.0

# API / live view
fastapi>=0.111.0
websockets>=12.0
uvicorn>=0.30.0

# Scoring
httpx>=0.27.0

# Fine-tuning (separate install, not runtime)
unsloth
torch>=2.3.0
transformers>=4.40.0
datasets>=2.20.0
```

---

## 14. The Interview Story This Architecture Tells

**One-liner:** "I built an autonomous penetration testing agent that evolves ReconX from a fixed-pipeline scanner into a reasoning system that can solve HackTheBox labs and find bugs in real bug bounty programs."

**What separates it from "I wired GPT-4 to nmap":**
1. The **cyclic planner loop** — not a fixed pipeline; decisions are made from actual findings
2. **Exploit verification** ("no PoC, no report") — not just scanner output aggregation
3. **Tech-stack-aware tool argument selection** — Nuclei tags from WhatWeb output, not a static list
4. **Long-term memory and playbook retrieval** — the agent improves across scans
5. **Scope gate as a hard engineering control** — not a prompt instruction that can be jailbroken
6. **Fine-tuned 7B model for structured outputs** — reduces API cost and latency in production

---

*NEXUS is a research and educational project. All testing must be performed on systems you own or have explicit written authorization to test. The authors accept no liability for misuse.*


<!-- v1.0 finalized 2026-09-10 -->
