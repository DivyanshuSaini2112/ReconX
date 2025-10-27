import subprocess
import os

class DirectoryFuzzer:
    def __init__(self, target, wordlist, threads, output_dir, gobuster_args=''):
        self.target = target
        self.wordlist = wordlist if wordlist else '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        self.threads = threads
        self.output_dir = output_dir
        self.gobuster_args = gobuster_args
        self.output_file = os.path.join(self.output_dir, 'dirfuzz.txt')

    def get_command(self):
        base_cmd = f'gobuster dir -u {self.target} -w {self.wordlist} -t {self.threads} -o {self.output_file}'

        if self.gobuster_args:
            base_cmd += f' {self.gobuster_args}'

        return base_cmd.split()

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            return self.parse_results()
        except FileNotFoundError:
            return {'error': "'gobuster' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Gobuster scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as e:
            # Gobuster exits with a non-zero status code on some errors (e.g., DNS), so we check stderr
            if 'error connecting to' in e.stderr.lower():
                 return {'error': f"Error running Gobuster: {e.stderr}"}
            # Otherwise, we can still parse the output
            return self.parse_results()


    def parse_results(self):
        try:
            with open(self.output_file, 'r') as f:
                # Example line: /images (Status: 301)
                # We want to extract the path
                results = [line.split(' ')[0] for line in f if line.strip()]
            return results
        except FileNotFoundError:
            print(f"[!] Gobuster output file not found: {self.output_file}")
            return None

def run(target, wordlist, threads, output_dir, gobuster_args):
    fuzzer = DirectoryFuzzer(target, wordlist, threads, output_dir, gobuster_args)
    return fuzzer.run_scan()
