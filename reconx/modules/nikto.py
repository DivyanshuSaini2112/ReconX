import os
import shlex
import subprocess
import tempfile
from typing import List, Optional, Union


class NiktoScanner:
    def __init__(self, target: str, output_dir: str, nikto_args: Optional[str] = None):
        self.target = self._normalise_target(target)
        self.output_dir = output_dir
        self.nikto_args = nikto_args or ''
        self.log_file = os.path.join(self.output_dir, 'nikto.log')

    def get_command(self, output_path: str) -> List[str]:
        command = [
            'nikto',
            '-h', self.target,
            '-o', output_path,
            '-Format', 'txt'
        ]
        if self.nikto_args:
            command.extend(shlex.split(self.nikto_args))
        return command

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[str], dict]:
        fd, temp_path = tempfile.mkstemp(suffix='.txt')
        os.close(fd)
        command = self.get_command(temp_path)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            self._write_log(command, result.stdout, result.stderr)
            with open(temp_path, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
            return self.parse_results(content)
        except FileNotFoundError:
            error_msg = "'nikto' command not found. Make sure it's installed and in your PATH."
            self._write_log(command, "", error_msg)
            return {'error': error_msg}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            return {'error': f"Nikto scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self._write_log(command, stdout, stderr, note="Nikto exited with a non-zero status.")
            content = ""
            if os.path.exists(temp_path):
                with open(temp_path, 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()
            parsed = self.parse_results(content)
            if parsed:
                return parsed
            return {'error': f"Error running Nikto: {stderr.strip() or 'unknown error'}"}
        finally:
            try:
                os.remove(temp_path)
            except (FileNotFoundError, OSError):
                pass

    def parse_results(self, raw_output: Optional[str]) -> List[str]:
        if not raw_output:
            return []

        findings: List[str] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith('+'):
                findings.append(line)
        return findings

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


def run(target, output_dir, nikto_args=None):
    scanner = NiktoScanner(target, output_dir, nikto_args=nikto_args)
    return scanner.run_scan()
