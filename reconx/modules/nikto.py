import subprocess
import os
from reconx.lib.utils import run_command_streaming

class NiktoScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'nikto.txt')
        self.log_file = os.path.join(self.output_dir, 'nikto.log')

    def get_command(self):
        # We use -o to specify the output file, and -Format txt is the default
        return ['nikto', '-h', self.target, '-o', self.output_file, '-Format', 'txt']

    def run_scan(self, timeout=None, status_callback=None):
        command = self.get_command()
        stderr_file = self.log_file + ".stderr"

        result = run_command_streaming(command, self.log_file, stderr_file, status_callback, timeout)

        if result and 'error' in result:
             if "timed out" in result['error']:
                 partial = self.parse_results()
                 if isinstance(partial, list) and partial:
                     return partial
             return result

        return self.parse_results()

    def parse_results(self):
        try:
            if not os.path.exists(self.output_file) or os.path.getsize(self.output_file) == 0:
                return []

            with open(self.output_file, 'r') as f:
                findings = [line.strip() for line in f if line.startswith('+ ')]
            return findings
        except FileNotFoundError:
            return {'error': f"Nikto output file not found: {self.output_file}"}

def run(target, output_dir):
    scanner = NiktoScanner(target, output_dir)
    return scanner.run_scan()
