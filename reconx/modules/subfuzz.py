import json
import os
import shlex
import subprocess
import tempfile
from typing import List, Optional, Union


class SubdomainFuzzer:
    def __init__(self, target: str, wordlist: Optional[str], threads: int, output_dir: str, ffuf_args: str = ''):
        self.target = target
        self.url = self._normalise_target(target)
        self.wordlist = wordlist or '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
        self.threads = threads
        self.output_dir = output_dir
        self.ffuf_args = ffuf_args or ''
        self.log_file = os.path.join(self.output_dir, 'subfuzz.log')

    def get_command(self, output_path: str) -> List[str]:
        base_cmd = [
            'ffuf',
            '-u', self.url,
            '-w', self.wordlist,
            '-H', f'Host: FUZZ.{self.target}',
            '-t', str(self.threads),
            '-o', output_path,
            '-of', 'json',
            '-s'
        ]

        if self.ffuf_args:
            base_cmd.extend(shlex.split(self.ffuf_args))

        return base_cmd

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[str], dict]:
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
            error_msg = "'ffuf' command not found. Make sure it's installed and in your PATH."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            return {'error': f"Subdomain fuzzing timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note="ffuf exited with a non-zero status.")
            if "Could not resolve host" in stderr:
                return {'error': f"Error running ffuf: Could not resolve host {self.target}"}
            parsed = self.parse_results(temp_path)
            if parsed:
                return parsed
            return {'error': f"Error running ffuf for subdomain fuzzing: {stderr.strip() or 'unknown error'}"}
        finally:
            try:
                os.remove(temp_path)
            except FileNotFoundError:
                pass

    def parse_results(self, json_path: str) -> List[str]:
        try:
            if not os.path.exists(json_path) or os.path.getsize(json_path) == 0:
                return []

            with open(json_path, 'r') as fh:
                data = json.load(fh)
            return [item['input']['FUZZ'] for item in data.get('results', []) if item.get('input')]
        except (json.JSONDecodeError, KeyError):
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


def run(target, wordlist, threads, output_dir, ffuf_args):
    fuzzer = SubdomainFuzzer(target, wordlist, threads, output_dir, ffuf_args)
    return fuzzer.run_scan()
