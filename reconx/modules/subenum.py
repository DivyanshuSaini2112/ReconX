import subprocess
import os

class SubdomainScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.output_file = os.path.join(self.output_dir, 'subdomains.txt')

    def get_command(self):
        return ['subfinder', '-d', self.target, '-o', self.output_file]

    def run_scan(self):
        command = self.get_command()
        print(f"[*] Running Subfinder scan: {' '.join(command)}")
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            print("[+] Subdomain enumeration completed.")
            return self.parse_results()
        except FileNotFoundError:
            print("[!] Error: 'subfinder' command not found. Make sure it's installed and in your PATH.")
            return None
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running Subfinder: {e.stderr}")
            return None

    def parse_results(self):
        try:
            with open(self.output_file, 'r') as f:
                subdomains = [line.strip() for line in f]
            return subdomains
        except FileNotFoundError:
            print(f"[!] Subfinder output file not found: {self.output_file}")
            return None

def run(target, output_dir):
    scanner = SubdomainScanner(target, output_dir)
    return scanner.run_scan()
