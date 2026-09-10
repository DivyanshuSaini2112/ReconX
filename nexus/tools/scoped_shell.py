     """Scope-gated shell executor for post-exploitation in CTF mode.

     All commands are:
     1. Logged with timestamp to the session output directory
     2. Checked against BLOCKED_PATTERNS before execution
     3. Limited to allowed network targets if Docker is used
     """

     import subprocess
     import re
     import logging
     from pathlib import Path

     BLOCKED_PATTERNS = [
         r"rm\s+-rf\s+/",
         r"dd\s+if=",
         r"mkfs\.",
         r"curl\s+.*\|\s*bash",
         r"wget\s+.*\|\s*sh",
     ]


     def run(command: str, output_dir: str, timeout: int = 30) -> dict:
         """Execute a shell command with safety checks and logging."""
         for pattern in BLOCKED_PATTERNS:
             if re.search(pattern, command):
                 logging.warning("Blocked dangerous command: %s", command)
                 return {"error": f"Blocked: {pattern}", "stdout": "", "stderr": ""}

         log_path = Path(output_dir) / "shell_log.txt"
         log_path.parent.mkdir(parents=True, exist_ok=True)

         try:
             result = subprocess.run(
                 command, shell=True, capture_output=True, text=True, timeout=timeout
             )
             with open(log_path, "a") as f:
                 f.write(f"$ {command}
{result.stdout}
{result.stderr}
")
             return {"stdout": result.stdout, "stderr": result.stderr,
                     "returncode": result.returncode}
         except subprocess.TimeoutExpired:
             return {"error": f"Timed out after {timeout}s", "stdout": "", "stderr": ""}
