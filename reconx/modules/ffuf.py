import subprocess
import os
import json

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

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            return self.parse_results()
        except FileNotFoundError:
            print("[!] Error: 'ffuf' command not found. Make sure it's installed and in your PATH.")
            return None
        except subprocess.TimeoutExpired:
            print(f"[!] ffuf scan timed out after {timeout} seconds.")
            return None
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running ffuf: {e.stderr}")
            return None

    def parse_results(self):
        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)
            # Extract the value of the 'FUZZ' keyword from the 'input' dictionary
            return [result['input']['FUZZ'] for result in data.get('results', [])]
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"[!] Error parsing ffuf JSON output: {e}")
            return None

def run(target, wordlist, threads, output_dir, ffuf_args):
    fuzzer = FfufFuzzer(target, wordlist, threads, output_dir, ffuf_args)
    return fuzzer.run_scan()
