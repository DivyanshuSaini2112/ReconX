import subprocess
import os
import re

class SqlmapScanner:
    def __init__(self, target, output_dir):
        if not target.startswith(('http://', 'https://')):
            self.target = f"http://{target}"
        else:
            self.target = target
        self.output_dir = os.path.join(output_dir, 'sqlmap')
        os.makedirs(self.output_dir, exist_ok=True)
        self.log_file = os.path.join(self.output_dir, 'log')

    def get_command(self):
        # Using --batch for non-interactive mode, and safe defaults for level and risk.
        # --crawl=1 is a safe way to discover links.
        # We output results to a dedicated directory.
        return [
            'sqlmap',
            '-u', self.target,
            '--batch',
            '--crawl=1',
            '--level=1',
            '--risk=1',
            '--output-dir', self.output_dir
        ]

    def run_scan(self):
        command = self.get_command()
        print(f"[*] Running SQLMap scan: {' '.join(command)}")
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            print("[+] SQLMap scan completed.")
            return self.parse_results()
        except FileNotFoundError:
            print("[!] Error: 'sqlmap' command not found. Make sure it's installed and in your PATH.")
            return None
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running SQLMap: {e.stderr}")
            return None

    def parse_results(self):
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Find all injectable parameters
            injectable_params = re.findall(r"parameter '#\d+\*' is vulnerable", content)

            # Find identified database versions
            db_versions = re.findall(r"back-end DBMS: (.*)", content)

            results = {
                'vulnerable': bool(injectable_params),
                'vulnerabilities': injectable_params,
                'db_versions': list(set(db_versions)) # Use set to get unique versions
            }
            return results
        except FileNotFoundError:
            print(f"[!] SQLMap log file not found: {self.log_file}")
            return None

def run(target, output_dir):
    scanner = SqlmapScanner(target, output_dir)
    return scanner.run_scan()
