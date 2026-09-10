import os
import shlex
import subprocess
from typing import Iterable, List, Optional, Union


class SubdomainScanner:
    """Runs Subfinder and normalises its output into a list of hostnames."""

    def __init__(self, target: str, output_dir: str, extra_args: Optional[str] = None):
        self.target = target
        self.output_dir = output_dir
        self.extra_args = extra_args or ""
        self.log_file = os.path.join(self.output_dir, 'subenum.log')

    def get_command(self) -> List[str]:
        base_cmd = ['subfinder', '-d', self.target, '-silent']
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
            error_msg = "'subfinder' command not found. Make sure it's installed and in your PATH."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stderr = exc.stderr or ""
            stdout = exc.output or ""
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            return {'error': f"Subfinder scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note="Subfinder returned a non-zero exit code.")
            # Even with non-zero exit codes Subfinder may have useful output.
            parsed = self.parse_results(stdout)
            if parsed:
                return parsed
            return {'error': f"Error running Subfinder: {stderr.strip() or 'unknown error'}"}

    def parse_results(self, raw_output: Union[str, Iterable[str]]) -> List[str]:
        if raw_output is None:
            return []

        if isinstance(raw_output, str):
            lines = raw_output.splitlines()
        else:
            lines = list(raw_output)

        return [line.strip() for line in lines if line.strip()]

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


def run(target: str, output_dir: str, extra_args: Optional[str] = None):
    scanner = SubdomainScanner(target, output_dir, extra_args=extra_args)
    return scanner.run_scan()
