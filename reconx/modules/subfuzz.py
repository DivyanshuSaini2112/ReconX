import subprocess
import os
import json
from reconx.lib.utils import run_command_streaming

class SubdomainFuzzer:
    def __init__(self, target, wordlist, threads, output_dir, ffuf_args=''):
        self.target = target
        self.wordlist = wordlist if wordlist else '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
        self.threads = threads
        self.output_dir = output_dir
        self.ffuf_args = ffuf_args
        self.output_file = os.path.join(self.output_dir, 'subfuzz.json')

    def get_command(self):
        # Use FUZZ keyword as a placeholder for the subdomain in the Host header
        base_cmd = f'ffuf -u http://{self.target} -w {self.wordlist} -H "Host: FUZZ.{self.target}" -t {self.threads} -o {self.output_file} -of json'

        if self.ffuf_args:
            base_cmd += f' {self.ffuf_args}'

        return base_cmd.split()

    def run_scan(self, timeout=None, status_callback=None):
        command = self.get_command()
        log_file = os.path.join(self.output_dir, 'subfuzz.log')
        stderr_file = os.path.join(self.output_dir, 'subfuzz.err')

        result = run_command_streaming(command, log_file, stderr_file, status_callback, timeout)

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
                data = json.load(f)
            # Extract the 'input' which is the subdomain that was found
            return [result['input']['FUZZ'] for result in data.get('results', [])]
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            return {'error': f"Error parsing ffuf JSON output for subdomain fuzzing: {e}"}

def run(target, wordlist, threads, output_dir, ffuf_args):
    fuzzer = SubdomainFuzzer(target, wordlist, threads, output_dir, ffuf_args)
    return fuzzer.run_scan()
