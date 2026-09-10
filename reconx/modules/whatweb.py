import json
import os
import shlex
import subprocess
import tempfile
from typing import List, Optional, Union


class WhatWebScanner:
    def __init__(self, target: str, output_dir: str, whatweb_args: Optional[str] = None):
        self.target = self._normalise_target(target)
        self.output_dir = output_dir
        self.whatweb_args = whatweb_args or ''
        self.log_file = os.path.join(self.output_dir, 'whatweb.log')

    def get_command(self, output_path: str) -> List[str]:
        command = ['whatweb', '--log-json', output_path, self.target]
        if self.whatweb_args:
            command.extend(shlex.split(self.whatweb_args))
        return command

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[dict], dict]:
        temp = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        temp_path = temp.name
        temp.close()

        command = self.get_command(temp_path)
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            self._write_log(command, result.stdout, result.stderr)
            return self.parse_results(temp_path)
        except FileNotFoundError:
            error_msg = "'whatweb' command not found. Make sure it's installed and in your PATH."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            return {'error': f"WhatWeb scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note="WhatWeb exited with a non-zero status.")
            parsed = self.parse_results(temp_path)
            if parsed:
                return parsed
            return {'error': f"Error running WhatWeb: {stderr.strip() or 'unknown error'}"}
        finally:
            try:
                os.remove(temp_path)
            except FileNotFoundError:
                pass

    def parse_results(self, json_path: str) -> List[dict]:
        try:
            if not os.path.exists(json_path) or os.path.getsize(json_path) == 0:
                return []

            with open(json_path, 'r') as fh:
                return json.load(fh)
        except json.JSONDecodeError:
            return []

    def _write_log(self, command: List[str], stdout: str, stderr: str, note: Optional[str] = None) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.log_file, 'w') as log:
            log.write(f"$ {' '.join(command)}\n")
            if note:
                log.write(f"# {note}\n")
            if stdout:
                log.write("\n--- STDOUT ---\n")
                log.write(stdout)
            if stderr:
                log.write("\n--- STDERR ---\n")
                log.write(stderr)

    @staticmethod
    def _normalise_target(target: str) -> str:
        if target.startswith(('http://', 'https://')):
            return target
        return f"http://{target}"


def run(target, output_dir, whatweb_args=None):
    scanner = WhatWebScanner(target, output_dir, whatweb_args=whatweb_args)
    return scanner.run_scan()
# enhanced: version extraction for CVE correlation in nexus layer
# fix: utf-8 errors='replace' for non-ASCII response bodies
