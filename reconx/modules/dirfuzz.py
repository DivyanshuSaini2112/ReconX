import subprocess
import os
from reconx.lib.utils import run_command_streaming

class DirectoryFuzzer:
    def __init__(self, target, wordlist, threads, output_dir, gobuster_args=''):
        self.target = target
        self.wordlist = wordlist if wordlist else '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        self.threads = threads
        self.output_dir = output_dir
        self.gobuster_args = gobuster_args
        self.output_file = os.path.join(self.output_dir, 'dirfuzz.txt')
        self.log_file = os.path.join(self.output_dir, 'dirfuzz.log')

    def get_command(self):
        base_cmd = f'gobuster dir -u {self.target} -w {self.wordlist} -t {self.threads} -o {self.output_file}'

        if self.gobuster_args:
            base_cmd += f' {self.gobuster_args}'

        return base_cmd.split()

    def run_scan(self, timeout=None, status_callback=None):
        command = self.get_command()
        stderr_file = self.log_file + ".stderr"

        # run_command_streaming writes STDOUT to self.log_file.
        # Gobuster writes findings to self.output_file (-o flag).
        result = run_command_streaming(command, self.log_file, stderr_file, status_callback, timeout)

        if result and 'error' in result:
            # Attempt to parse partial results on timeout
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
                results = [line.strip() for line in f if line.strip()]
            return results
        except FileNotFoundError:
            return {'error': f"Gobuster output file not found: {self.output_file}"}

def run(target, wordlist, threads, output_dir, gobuster_args):
    fuzzer = DirectoryFuzzer(target, wordlist, threads, output_dir, gobuster_args)
    return fuzzer.run_scan()
