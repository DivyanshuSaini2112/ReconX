"""QLoRA fine-tuning config for Qwen2.5-7B-Instruct.
Uses Unsloth for 4x speed and 70% VRAM reduction vs standard HuggingFace Trainer.

Target metrics post-training:
- Structured output compliance: >95% (valid AttackSurface JSON)
- Planner decision quality: human eval on 20 held-out HTB scenarios
- False positive rate in vuln classification: <10%

Usage (on RunPod 2xA100):
  pip install unsloth
  python nexus_finetune/train.py --dataset ./dataset/ --output ./finetuned/
"""

MODEL_ID = "Qwen/Qwen2.5-7B-Instruct"
LORA_RANK = 16
LORA_ALPHA = 32
BATCH_SIZE = 4
GRAD_ACCUM = 8
LEARNING_RATE = 2e-4
MAX_STEPS = 2000
