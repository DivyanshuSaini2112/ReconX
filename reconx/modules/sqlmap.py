import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional, Union


class SqlmapScanner:
    def __init__(self, target: str, output_dir: str, sqlmap_args: Optional[str] = None):
        if not target.startswith(('http://', 'https://')):
            self.target = f"http://{target}"
        else:
            self.target = target
        self.output_dir = output_dir
        self.sqlmap_args = sqlmap_args or ''
        self.log_file = os.path.join(self.output_dir, 'sqlmap.log')

    def get_command(self, temp_dir: str):
        command = [
            'sqlmap',
            '-u', self.target,
            '--batch',
            '--crawl=1',
            '--level=1',
            '--risk=1',
            '--output-dir', temp_dir
        ]
        if self.sqlmap_args:
            command.extend(self.sqlmap_args.split())
        return command

    def run_scan(self, timeout: Optional[int] = None) -> Union[Dict, dict]:
        temp_dir = tempfile.mkdtemp(prefix='reconx-sqlmap-')
        command = self.get_command(temp_dir)
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            self._write_log_header(command, result.stdout, result.stderr)
            log_path = self._find_log(temp_dir)
            if not log_path:
                return {'error': 'SQLMap log not found; check sqlmap.log for details.'}
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
            self._append_sqlmap_log(content)
            return self.parse_results(content)
        except FileNotFoundError:
            self._write_log_header(command, "", "'sqlmap' command not found.")
            return {'error': "'sqlmap' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired as exc:
            stdout = exc.output or ""
            stderr = exc.stderr or ""
            self._write_log_header(command, stdout, stderr, note=f"Timeout after {timeout} seconds.")
            return {'error': f"SQLMap scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self._write_log_header(command, stdout, stderr, note="sqlmap exited with a non-zero status.")
            return {'error': f"Error running SQLMap: {stderr.strip() or 'unknown error'}"}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def parse_results(self, log_content: Optional[str]) -> Dict[str, Union[bool, list]]:
        if not log_content:
            return {'vulnerable': False, 'vulnerabilities': [], 'db_versions': []}

        injectable_params = re.findall(r"parameter '([^']+)' is vulnerable", log_content)
        db_versions = re.findall(r"back-end DBMS: (.*)", log_content)

        return {
            'vulnerable': bool(injectable_params),
            'vulnerabilities': injectable_params,
            'db_versions': sorted(set(db_versions))
        }

    def _find_log(self, temp_dir: str) -> Optional[Path]:
        path = Path(temp_dir)
        for log_file in path.rglob('log'):
            return log_file
        return None

    def _write_log_header(self, command, stdout: str, stderr: str, note: Optional[str] = None) -> None:
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
            log.write("\n")

    def _append_sqlmap_log(self, content: str) -> None:
        with open(self.log_file, 'a') as log:
            log.write("--- SQLMAP LOG ---\n")
            log.write(content)


def run(target, output_dir, sqlmap_args=None):
    scanner = SqlmapScanner(target, output_dir, sqlmap_args=sqlmap_args)
    return scanner.run_scan()
