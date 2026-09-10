import os
import shlex
import subprocess
from typing import List, Optional, Union


class LabSubdomainScanner:
    """Fallback subdomain enumeration tailored for internal lab environments."""

    def __init__(self, target: str, output_dir: str, wordlist: Optional[str], threads: int, extra_args: Optional[str] = None):
        self.target = target
        self.wordlist = wordlist or '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt'
        self.threads = threads
        self.extra_args = extra_args or ""
        self.output_dir = output_dir
        self.log_file = os.path.join(self.output_dir, 'lab-subenum.log')

    def get_command(self) -> List[str]:
        base_cmd = [
            'gobuster',
            'dns',
            '--domain', self.target,
            '-w', self.wordlist,
            '-t', str(self.threads),
            '--no-progress',
            '--quiet'
        ]
        if self.extra_args:
            base_cmd.extend(shlex.split(self.extra_args))
        return base_cmd

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[str], dict]:
        command = self.get_command()
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            self._write_log(command, result.stdout, result.stderr)
            return self.parse_results(result.stdout)
        except FileNotFoundError:
            error_msg = "'gobuster' command not found. Install it to use lab mode."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            return {'error': f"Lab subdomain scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note="Gobuster returned a non-zero exit code.")
            parsed = self.parse_results(stdout)
            if parsed:
                return parsed
            return {'error': f"Gobuster DNS scan failed: {stderr.strip() or 'unknown error'}"}

    def parse_results(self, raw_output: Optional[str]) -> List[str]:
        if not raw_output:
            return []

        subdomains: List[str] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith('found:'):
                _, value = line.split(':', 1)
                subdomains.append(value.strip())
            else:
                subdomains.append(line)
        return subdomains

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


def run(target: str, output_dir: str, wordlist: Optional[str], threads: int, extra_args: Optional[str] = None):
    scanner = LabSubdomainScanner(target, output_dir, wordlist, threads, extra_args)
    return scanner.run_scan()
