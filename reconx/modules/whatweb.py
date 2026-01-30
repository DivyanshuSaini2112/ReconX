import subprocess
import json
import os
from reconx.lib.utils import run_command_streaming

class WhatWebScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'whatweb.json')

    def get_command(self):
        # We use --log-json to get structured output
        return ['whatweb', '--log-json', self.output_file, self.target]

    def run_scan(self, timeout=None, status_callback=None):
        command = self.get_command()
        log_file = os.path.join(self.output_dir, 'whatweb.log')
        stderr_file = os.path.join(self.output_dir, 'whatweb.err')

        result = run_command_streaming(command, log_file, stderr_file, status_callback, timeout)

        if result and 'error' in result:
             return result

        return self.parse_results()

    def parse_results(self):
        try:
            with open(self.output_file, 'r') as f:
                # WhatWeb's JSON output is a list of objects, one per target
                results = json.load(f)
            return results
        except (FileNotFoundError, json.JSONDecodeError) as e:
            # print(f"[!] Error parsing WhatWeb JSON output: {e}")
            return None

def run(target, output_dir):
    scanner = WhatWebScanner(target, output_dir)
    return scanner.run_scan()
