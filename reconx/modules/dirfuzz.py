import os
import shlex
import subprocess
from typing import List, Optional, Union


class DirectoryFuzzer:
    def __init__(self, target: str, wordlist: Optional[str], threads: int, output_dir: str, gobuster_args: str = ''):
        self.target = self._normalise_target(target)
        self.wordlist = wordlist or '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        self.threads = threads
        self.output_dir = output_dir
        self.gobuster_args = gobuster_args or ''
        self.log_file = os.path.join(self.output_dir, 'dirfuzz.log')

    def get_command(self) -> List[str]:
        base_cmd = [
            'gobuster',
            'dir',
            '-u', self.target,
            '-w', self.wordlist,
            '-t', str(self.threads),
            '--no-progress',
            '--quiet'
        ]

        if self.gobuster_args:
            base_cmd.extend(shlex.split(self.gobuster_args))

        return base_cmd

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[str], dict]:
        command = self.get_command()
        self._write_log_start(command)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            self._write_log(command, result.stdout, result.stderr)
            return self.parse_results(result.stdout)
        except FileNotFoundError:
            error_msg = "'gobuster' command not found. Make sure it's installed and in your PATH."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            parsed = self.parse_results(stdout)
            if parsed:
                return parsed  # Return partial results
            return {'error': f"Gobuster scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note="Gobuster exited with a non-zero status.")
            parsed = self.parse_results(stdout)
            if parsed:
                return parsed
            # Check for connection issues to give clearer feedback
            if 'error on parsing the server response' in stderr.lower() or 'error connecting to' in stderr.lower():
                return {'error': f"Error running Gobuster: {stderr.strip()}"}
            return {'error': f"Gobuster failed: {stderr.strip() or 'unknown error'}"}

    def parse_results(self, raw_output: Optional[str]) -> List[str]:
        if not raw_output:
            return []

        results: List[str] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith('/'):
                path = line.split(' ', 1)[0]
                results.append(path)
            elif 'http' in line:
                # Some versions include full URLs
                parts = line.split(' ', 1)
                results.append(parts[0])

        return results

    def _write_log_start(self, command: List[str]) -> None:
        """Write initial log so user sees module has started."""
        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.log_file, 'w') as log:
            log.write(f"$ {' '.join(command)}\n")
            log.write("# Scan started... (output will append when complete)\n")

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


def run(target, wordlist, threads, output_dir, gobuster_args):
    fuzzer = DirectoryFuzzer(target, wordlist, threads, output_dir, gobuster_args)
    return fuzzer.run_scan()
