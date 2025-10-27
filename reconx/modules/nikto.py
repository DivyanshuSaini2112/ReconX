import subprocess
import os

class NiktoScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'nikto.txt')

    def get_command(self):
        # We use -o to specify the output file, and -Format txt is the default
        return ['nikto', '-h', self.target, '-o', self.output_file, '-Format', 'txt']

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            return self.parse_results()
        except FileNotFoundError:
            print("[!] Error: 'nikto' command not found. Make sure it's installed and in your PATH.")
            return None
        except subprocess.TimeoutExpired:
            print(f"[!] Nikto scan timed out after {timeout} seconds.")
            return None
        except subprocess.CalledProcessError as e:
            # Nikto often exits with a non-zero status code, so we'll parse the output anyway
            print(f"[!] Nikto exited with a non-zero status, but we will attempt to parse the output. Stderr: {e.stderr}")
            return self.parse_results()

    def parse_results(self):
        try:
            with open(self.output_file, 'r') as f:
                # We'll extract lines that start with a '+'
                findings = [line.strip() for line in f if line.startswith('+ ')]
            return findings
        except FileNotFoundError:
            print(f"[!] Nikto output file not found: {self.output_file}")
            return None

def run(target, output_dir):
    scanner = NiktoScanner(target, output_dir)
    return scanner.run_scan()
