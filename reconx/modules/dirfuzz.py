import subprocess
import os
import json

class DirectoryFuzzer:
    def __init__(self, target, profile, wordlist, threads, output_dir, ffuf_args=''):
        if not target.startswith(('http://', 'https://')):
            self.target = f"http://{target}"
        else:
            self.target = target

        self.profile = profile
        self.wordlist = wordlist
        self.threads = threads
        self.output_dir = output_dir
        self.ffuf_args = ffuf_args
        self.output_file = os.path.join(self.output_dir, 'dirfuzz.json')
        self.log_file = os.path.join(self.output_dir, 'dirfuzz.log')

        if not self.wordlist:
            if self.profile == 'fast':
                self.wordlist = '/usr/share/wordlists/dirb/common.txt'
            else:
                self.wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'

    def get_command(self):
        url = self.target if self.target.endswith('/') else self.target + '/'
        url += 'FUZZ'

        base_cmd = f'ffuf -u {url} -w {self.wordlist} -t {self.threads} -o {self.output_file} -of json'

        if self.ffuf_args:
            base_cmd += f' {self.ffuf_args}'

        return base_cmd.split()

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

            with open(self.log_file, 'w') as f:
                f.write("--- FFUF STDOUT ---\n")
                f.write(result.stdout)
                f.write("\n--- FFUF STDERR ---\n")
                f.write(result.stderr)

            if result.returncode != 0 and "ERROR" in result.stderr.upper():
                 return {'error': f"Error running ffuf: {result.stderr}"}

            return self.parse_results()

        except FileNotFoundError:
            return {'error': "'ffuf' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"ffuf scan timed out after {timeout} seconds. Check dirfuzz.log for partial results."}
        except Exception as e:
            with open(self.log_file, 'w') as f:
                f.write(f"An unexpected error occurred: {e}\n")
            return {'error': f"An unexpected error occurred with ffuf: {e}"}

    def parse_results(self):
        try:
            if not os.path.exists(self.output_file) or os.path.getsize(self.output_file) == 0:
                return []

            with open(self.output_file, 'r') as f:
                data = json.load(f)
            return [result.get('url') for result in data.get('results', [])]
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return {'error': f"Error parsing ffuf JSON output: {e}"}

def run(target, profile, wordlist, threads, output_dir, ffuf_args):
    fuzzer = DirectoryFuzzer(target, profile, wordlist, threads, output_dir, ffuf_args)
    return fuzzer.run_scan()
