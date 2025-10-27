import subprocess
import os
import json

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

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            return self.parse_results()
        except FileNotFoundError:
            return {'error': "'ffuf' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Subdomain fuzzing timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as e:
            return {'error': f"Error running ffuf for subdomain fuzzing: {e.stderr}"}

    def parse_results(self):
        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)
            # Extract the 'input' which is the subdomain that was found
            return [result['input']['FUZZ'] for result in data.get('results', [])]
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"[!] Error parsing ffuf JSON output for subdomain fuzzing: {e}")
            return None

def run(target, wordlist, threads, output_dir, ffuf_args):
    fuzzer = SubdomainFuzzer(target, wordlist, threads, output_dir, ffuf_args)
    return fuzzer.run_scan()
