import subprocess
import os
from reconx.lib.utils import run_command_streaming

class SubdomainScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'subdomains.txt')

    def get_command(self):
        return ['subfinder', '-d', self.target, '-o', self.output_file]

    def run_scan(self, timeout=None, status_callback=None):
        command = self.get_command()
        log_file = os.path.join(self.output_dir, 'subfinder.log')
        stderr_file = os.path.join(self.output_dir, 'subfinder.err')

        result = run_command_streaming(command, log_file, stderr_file, status_callback, timeout)

        if result and 'error' in result:
             if "timed out" in result['error']:
                 return self.parse_results()
             return result

        return self.parse_results()

    def parse_results(self):
        try:
            if not os.path.exists(self.output_file) or os.path.getsize(self.output_file) == 0:
                return []

            with open(self.output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            return subdomains
        except FileNotFoundError:
            return {'error': f"Subfinder output file not found: {self.output_file}"}
        except Exception as e:
            return {'error': f"An unexpected error occurred while parsing Subfinder results: {e}"}

def run(target, output_dir):
    scanner = SubdomainScanner(target, output_dir)
    return scanner.run_scan()
