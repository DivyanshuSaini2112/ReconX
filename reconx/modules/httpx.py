"""
httpx module - ProjectDiscovery httpx for HTTP probing (title, status, tech).
Runs after subenum to probe discovered hosts; can also run on a single target URL.
"""
import json
import os
import shlex
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Union


class HttpxScanner:
    def __init__(self, target: str, output_dir: str, httpx_args: Optional[str] = None):
        self.target = self._normalise_target(target)
        self.output_dir = output_dir
        self.httpx_args = httpx_args or ''
        self.log_file = os.path.join(self.output_dir, 'httpx.log')

    def get_command(self, output_path: str) -> List[str]:
        command = [
            'httpx',
            '-u', self.target,
            '-silent',
            '-json',
            '-title',
            '-status-code',
            '-tech-detect',
            '-web-server',
            '-o', output_path
        ]
        if self.httpx_args:
            command.extend(shlex.split(self.httpx_args))
        return command

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[Dict[str, Any]], dict]:
        fd, temp_path = tempfile.mkstemp(suffix='.jsonl')
        os.close(fd)
        command = self.get_command(temp_path)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode('utf-8', errors='replace')
            if isinstance(stderr, bytes):
                stderr = stderr.decode('utf-8', errors='replace')
            self._write_log(command, stdout, stderr)
            return self.parse_results(temp_path)
        except FileNotFoundError:
            error_msg = "'httpx' command not found. Install from https://github.com/projectdiscovery/httpx."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or b""
            stderr = exc.stderr or b""
            stdout = stdout.decode('utf-8', errors='replace') if isinstance(stdout, bytes) else (stdout or "")
            stderr = stderr.decode('utf-8', errors='replace') if isinstance(stderr, bytes) else (stderr or "")
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            parsed = self.parse_results(temp_path)
            if parsed:
                return parsed
            return {'error': f"httpx timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = (exc.stdout or b"").decode('utf-8', errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = (exc.stderr or b"").decode('utf-8', errors='replace') if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            self._write_log(command, stdout, stderr, note="httpx exited with non-zero status.")
            parsed = self.parse_results(temp_path)
            if parsed:
                return parsed
            return {'error': f"httpx failed: {stderr.strip() or 'unknown error'}"}
        finally:
            try:
                os.remove(temp_path)
            except (FileNotFoundError, OSError):
                pass

    def parse_results(self, output_path: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            return results
        with open(output_path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results

    def _write_log(self, command: List[str], stdout: str, stderr: str, note: Optional[str] = None) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.log_file, 'w', encoding='utf-8') as log:
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


def run(target: str, output_dir: str, httpx_args: Optional[str] = None):
    scanner = HttpxScanner(target, output_dir, httpx_args=httpx_args)
    return scanner.run_scan()
