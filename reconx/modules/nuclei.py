import subprocess
import os
import json

class NucleiScanner:
    def __init__(self, target, profile, output_dir, nuclei_args=''):
        if not target.startswith(('http://', 'https://')):
            self.target = f"http://{target}"
        else:
            self.target = target

        self.profile = profile
        self.output_dir = output_dir
        self.nuclei_args = nuclei_args
        self.output_file = os.path.join(self.output_dir, 'nuclei.json')
        self.log_file = os.path.join(self.output_dir, 'nuclei.log')

    def get_command(self):
        base_cmd = f'nuclei -u {self.target} -o {self.output_file} -json -silent'

        if self.nuclei_args:
            base_cmd += f' {self.nuclei_args}'

        # Add profile-specific arguments
        if self.profile == 'fast':
            # Use tags to run a faster scan, excluding more intensive templates
            base_cmd += ' -tags cve,default,vulnerability'
        elif self.profile == 'deep':
            # Run a more comprehensive scan
             base_cmd += ' -tags cve,default,vulnerability,config,technologies,fuzz'

        return base_cmd.split()

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

            with open(self.log_file, 'w') as f:
                f.write("--- NUCLEI STDOUT ---\n")
                f.write(result.stdout)
                f.write("\n--- NUCLEI STDERR ---\n")
                f.write(result.stderr)

            if result.returncode != 0 and "ERROR" in result.stderr.upper():
                 return {'error': f"Error running Nuclei: {result.stderr}"}

            return self.parse_results()

        except FileNotFoundError:
            return {'error': "'nuclei' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Nuclei scan timed out after {timeout} seconds. Check nuclei.log for partial results."}
        except Exception as e:
            with open(self.log_file, 'w') as f:
                f.write(f"An unexpected error occurred: {e}\n")
            return {'error': f"An unexpected error occurred with Nuclei: {e}"}

    def parse_results(self):
        try:
            if not os.path.exists(self.output_file) or os.path.getsize(self.output_file) == 0:
                return []

            with open(self.output_file, 'r') as f:
                # Each line in the JSON output is a separate JSON object
                results = [json.loads(line) for line in f]
            return results
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return {'error': f"Error parsing Nuclei JSON output: {e}"}

def run(target, profile, output_dir, nuclei_args):
    scanner = NucleiScanner(target, profile, output_dir, nuclei_args)
    return scanner.run_scan()
