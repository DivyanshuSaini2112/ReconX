import subprocess
import os

class SubdomainScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'subdomains.txt')

    def get_command(self):
        return ['subfinder', '-d', self.target, '-o', self.output_file]

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            if result.stderr:
                # Subfinder often prints non-fatal errors to stderr
                with open(os.path.join(self.output_dir, 'subfinder.log'), 'w') as f:
                    f.write(result.stderr)

            return self.parse_results()
        except FileNotFoundError:
            return {'error': "'subfinder' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Subfinder scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as e:
            return {'error': f"Error running Subfinder: {e.stderr}"}

    def parse_results(self):
        try:
            if os.path.getsize(self.output_file) == 0:
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
