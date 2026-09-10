"""
nuclei module - ProjectDiscovery nuclei for vulnerability scanning.
Uses -l targets.txt, tags (cve,misconfig,exposure,critical,high,rce), etags (fuzz,dos,headless),
host-spray strategy, and JSONL output. No -silent so progress is written to nuclei.log.
"""
import json
import os
import shlex
import subprocess
import tempfile
from typing import List, Optional, Union


class NucleiScanner:
    def __init__(self, target: str, output_dir: str, nuclei_args: Optional[str] = None):
        self.target = self._normalise_target(target)
        self.output_dir = output_dir
        self.nuclei_args = nuclei_args or ''
        self.log_file = os.path.join(self.output_dir, 'nuclei.log')

    def get_command(self, targets_path: str, output_path: str) -> List[str]:
        command = [
            'nuclei',
            '-l', targets_path,
            '-tags', 'cve,misconfig,exposure,critical,high,rce',
            '-etags', 'fuzz,dos,headless',
            '-ss', 'host-spray',
            '-c', '50',
            '-bs', '25',
            '-timeout', '5',
            '-retries', '1',
            '-jsonl',
            '-o', output_path
        ]
        if self.nuclei_args:
            command.extend(shlex.split(self.nuclei_args))
        return command

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[dict], dict]:
        fd_out, temp_out = tempfile.mkstemp(suffix='.jsonl')
        os.close(fd_out)
        fd_tgt, targets_path = tempfile.mkstemp(suffix='.targets.txt')
        try:
            with os.fdopen(fd_tgt, 'w') as f:
                f.write(self.target + '\n')
        except OSError:
            try:
                os.close(fd_tgt)
            except OSError:
                pass
            try:
                os.remove(targets_path)
            except OSError:
                pass
            return {'error': 'Failed to write targets file for nuclei.'}

        command = self.get_command(targets_path, temp_out)
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
            return self.parse_results(temp_out)
        except FileNotFoundError:
            error_msg = "'nuclei' command not found. Install from https://github.com/projectdiscovery/nuclei."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or b""
            stderr = exc.stderr or b""
            stdout = stdout.decode('utf-8', errors='replace') if isinstance(stdout, bytes) else (stdout or "")
            stderr = stderr.decode('utf-8', errors='replace') if isinstance(stderr, bytes) else (stderr or "")
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            parsed = self.parse_results(temp_out)
            if parsed:
                return parsed
            return {'error': f"nuclei timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = (exc.stdout or b"").decode('utf-8', errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = (exc.stderr or b"").decode('utf-8', errors='replace') if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            self._write_log(command, stdout, stderr, note="nuclei exited with non-zero status.")
            parsed = self.parse_results(temp_out)
            if parsed:
                return parsed
            return {'error': f"nuclei failed: {stderr.strip() or 'unknown error'}"}
        finally:
            for p in (temp_out, targets_path):
                try:
                    os.remove(p)
                except (FileNotFoundError, OSError):
                    pass

    def parse_results(self, output_path: str) -> List[dict]:
        results: List[dict] = []
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


def run(target: str, output_dir: str, nuclei_args: Optional[str] = None):
    scanner = NucleiScanner(target, output_dir, nuclei_args=nuclei_args)
    return scanner.run_scan()
# planner can now override tags via nuclei_args based on WhatWeb tech detection
