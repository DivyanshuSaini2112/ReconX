import subprocess
import os

class NiktoScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'nikto.txt')
        self.log_file = os.path.join(self.output_dir, 'nikto.log')

    def get_command(self):
        # We use -o to specify the output file, and -Format txt is the default
        return ['nikto', '-h', self.target, '-o', self.output_file, '-Format', 'txt']

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

            with open(self.log_file, 'w') as f:
                f.write("--- NIKTO STDOUT ---\n")
                f.write(result.stdout)
                f.write("\n--- NIKTO STDERR ---\n")
                f.write(result.stderr)

            # Nikto often exits with a non-zero status code, so we'll parse the output anyway
            return self.parse_results()

        except FileNotFoundError:
            return {'error': "'nikto' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            # Even on timeout, Nikto might have written partial results
            with open(self.log_file, 'a') as f:
                f.write("\n--- TIMEOUT ERROR ---\n")
                f.write(f"Nikto scan timed out after {timeout} seconds.")
            return {'error': f"Nikto scan timed out after {timeout} seconds. Check nikto.log for partial results."}
        except Exception as e:
            with open(self.log_file, 'w') as f:
                f.write(f"An unexpected error occurred: {e}\n")
            return {'error': f"An unexpected error occurred with Nikto: {e}"}

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
