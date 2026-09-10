"""Dataset builders for fine-tuning Qwen2.5-7B on NEXUS-specific tasks.

Task 1: Tool output parsing (nmap/whatweb -> AttackSurface JSON)
Task 2: Planner decisions (AttackSurface + findings -> next_actions JSON)
Task 3: Vulnerability descriptions (raw finding -> structured RiskFinding)

Total target: ~37K examples
Training cost estimate: $80-120 on RunPod 2xA100
Framework: Unsloth QLoRA (4x faster than HuggingFace Trainer, 70% less VRAM)
"""
