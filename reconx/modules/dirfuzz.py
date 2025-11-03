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
        self.log_file = os.path.join(self.output_dir, 'dirfuzz.log')

    def get_command(self):
        base_cmd = f'gobuster dir -u {self.target} -w {self.wordlist} -t {self.threads} -o {self.output_file}'

        if self.gobuster_args:
            base_cmd += f' {self.gobuster_args}'

        return base_cmd.split()

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

            with open(self.log_file, 'w') as f:
                f.write("--- GOBUSter STDOUT ---\n")
                f.write(result.stdout)
                f.write("\n--- GOBUSter STDERR ---\n")
                f.write(result.stderr)

            # Check for common errors in stderr, even if the process doesn't fail
            if 'error connecting to' in result.stderr.lower():
                 return {'error': f"Error running Gobuster: {result.stderr}"}

            return self.parse_results()

        except FileNotFoundError:
            return {'error': "'gobuster' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Gobuster scan timed out after {timeout} seconds. Check dirfuzz.log for partial results."}
        except Exception as e:
            with open(self.log_file, 'w') as f:
                f.write(f"An unexpected error occurred: {e}\n")
            return {'error': f"An unexpected error occurred with Gobuster: {e}"}

    def parse_results(self):
        try:
            if not os.path.exists(self.output_file) or os.path.getsize(self.output_file) == 0:
                return []

            with open(self.output_file, 'r') as f:
                results = [line.split(' ')[0] for line in f if line.strip()]
            return results
        except FileNotFoundError:
            return {'error': f"Gobuster output file not found: {self.output_file}"}

def run(target, wordlist, threads, output_dir, gobuster_args):
    fuzzer = DirectoryFuzzer(target, wordlist, threads, output_dir, gobuster_args)
    return fuzzer.run_scan()
