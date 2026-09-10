# NEXUS Research Notes

## Agentic Pentesting Survey

- PentestGPT (USENIX 2024): PTT-based reasoning, human-in-the-loop
- Shannon (Keygraph): source-aware, Playwright exploit verification, Temporal
- Key gap: no open tool does cyclic planning + exploit verification together

## Architecture Decision: LangGraph

LangGraph chosen over CrewAI because:
1. Native cyclic graph support (essential for adaptive recon loops)
2. Send API for parallel agent dispatch
3. Built-in SQLite checkpointing for interrupted scans

## LLM Routing Strategy

Groq free tier as primary (llama-3.3-70b-versatile, 60 RPM).
DeepSeek-R1 for reasoning tasks (also free on Groq).
Gemini 2.0 Flash for long-context analysis (1M token window, free).
Claude Sonnet for exploit payload generation (premium, opt-in only).
