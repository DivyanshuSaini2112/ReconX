import subprocess
import json
import os

class WhatWebScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'whatweb.json')

    def get_command(self):
        # We use --log-json to get structured output
        return ['whatweb', '--log-json', self.output_file, self.target]

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            return self.parse_results()
        except FileNotFoundError:
            return {'error': "'whatweb' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"WhatWeb scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as e:
            return {'error': f"Error running WhatWeb: {e.stderr}"}

    def parse_results(self):
        try:
            with open(self.output_file, 'r') as f:
                # WhatWeb's JSON output is a list of objects, one per target
                results = json.load(f)
            return results
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Error parsing WhatWeb JSON output: {e}")
            return None

def run(target, output_dir):
    scanner = WhatWebScanner(target, output_dir)
    return scanner.run_scan()
