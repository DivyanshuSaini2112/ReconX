import subprocess
import os
import json
from reconx.lib.utils import run_command_streaming

class FfufFuzzer:
    def __init__(self, target, wordlist, threads, output_dir, ffuf_args=''):
        if not target.startswith(('http://', 'https://')):
            self.target = f"http://{target}"
        else:
            self.target = target
        self.wordlist = wordlist if wordlist else '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        self.threads = threads
        self.output_dir = output_dir
        self.ffuf_args = ffuf_args
        self.output_file = os.path.join(self.output_dir, 'ffuf_fuzz.json')

    def get_command(self):
        # Use FUZZ keyword for ffuf
        url = self.target if self.target.endswith('/') else self.target + '/'
        url += 'FUZZ'

        # We use -o to specify the output file and -of json for the format
        base_cmd = f'ffuf -u {url} -w {self.wordlist} -t {self.threads} -o {self.output_file} -of json'

        if self.ffuf_args:
            base_cmd += f' {self.ffuf_args}'

        return base_cmd.split()

    def run_scan(self, timeout=None, status_callback=None):
        command = self.get_command()
        log_file = os.path.join(self.output_dir, 'ffuf.log')
        stderr_file = os.path.join(self.output_dir, 'ffuf.err')

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
            with open(self.output_file, 'r') as f:
                data = json.load(f)
            # Extract the value of the 'FUZZ' keyword from the 'input' dictionary
            return [result['input']['FUZZ'] for result in data.get('results', [])]
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            # print(f"[!] Error parsing ffuf JSON output: {e}") # Don't print to console in library code
            return None

def run(target, wordlist, threads, output_dir, ffuf_args):
    fuzzer = FfufFuzzer(target, wordlist, threads, output_dir, ffuf_args)
    return fuzzer.run_scan()
