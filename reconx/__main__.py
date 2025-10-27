import argparse
import sys
import os
import datetime
from reconx.modules import nmap, subenum, dirfuzz, whatweb, nikto, sqlmap
from reconx.lib import output

def main():
    parser = argparse.ArgumentParser(
        description='A CLI-first reconnaissance tool for Kali Linux.',
        epilog='Example: reconx -t example.com --profile default --modules nmap,subenum,dirfuzz,nikto,whatweb --sqlmap'
    )

    # Required arguments
    parser.add_argument('-t', '--target', required=True, help='The target IP, domain, or CIDR.')

    # Module selection
    parser.add_argument('--modules', default='nmap,subenum,dirfuzz,whatweb,nikto', help='Comma-separated list of modules to run (e.g., nmap,subenum,dirfuzz).')

    # Scan configuration
    parser.add_argument('--profile', choices=['fast', 'default', 'deep'], default='default', help='Scan profile (fast, default, deep).')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads for fuzzing/discovery.')
    parser.add_argument('--wordlist', help='Path to a custom wordlist for directory fuzzing.')

    # Output configuration
    parser.add_argument('--out', default='./results', help='Directory to save results to.')

    # Advanced options
    parser.add_argument('--nmap-args', help='Custom arguments for Nmap (e.g., "--nmap-args=\'-sV -T4\'").', default='')
    parser.add_argument('--gobuster-args', help='Custom arguments for Gobuster/dirsearch.', default='')
    parser.add_argument('--sqlmap', action='store_true', help='Explicitly enable the SQLMap module.')
    parser.add_argument('--no-exec', action='store_true', help='Print planned commands without executing them.')

    args = parser.parse_args()

    print("--- ReconX: Automated Reconnaissance Tool ---")

    if not args.no_exec:
        print("\nWARNING: This tool is intended for authorized security testing only.")
        print("You must have explicit, written permission from the target system's owner.")

        try:
            consent = input("I confirm I have written authorization to scan this target (type YES): ")
            if consent.strip().upper() != 'YES':
                print("Consent not given. Exiting.")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\nScan cancelled by user. Exiting.")
            sys.exit(0)

    print(f"\n[+] Target: {args.target}")
    print(f"[+] Profile: {args.profile}")

    enabled_modules = [m.strip() for m in args.modules.split(',')]
    if args.sqlmap:
        enabled_modules.append('sqlmap')
    print(f"[+] Modules: {', '.join(enabled_modules)}")

    # Create output directory
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    target_name = args.target.replace('/', '_') # Sanitize target name for directory
    output_dir = os.path.join(args.out, f"{target_name}-{timestamp}")
    if not args.no_exec:
        os.makedirs(output_dir, exist_ok=True)
    print(f"[+] Output directory: {output_dir}")

    results = {}

    # --- Module Execution ---
    if 'nmap' in enabled_modules:
        nmap_scanner = nmap.NmapScanner(args.target, args.profile, output_dir, args.nmap_args)
        if args.no_exec:
            print(f"  [NMAP CMD]: {' '.join(nmap_scanner.get_command())}")
        else:
            print("\n[+] Starting Nmap scan...")
            nmap_results = nmap_scanner.run_scan()
            if nmap_results:
                results['nmap'] = nmap_results
                print("[+] Nmap results processed.")

    if 'subenum' in enabled_modules:
        subdomain_scanner = subenum.SubdomainScanner(args.target, output_dir)
        if args.no_exec:
            print(f"  [SUBFINDER CMD]: {' '.join(subdomain_scanner.get_command())}")
        else:
            print("\n[+] Starting Subdomain Enumeration...")
            subenum_results = subdomain_scanner.run_scan()
            if subenum_results:
                results['subdomains'] = subenum_results
                print("[+] Subdomain results processed.")

    if 'dirfuzz' in enabled_modules:
        dirfuzz_fuzzer = dirfuzz.DirectoryFuzzer(args.target, args.wordlist, args.threads, output_dir, args.gobuster_args)
        if args.no_exec:
            print(f"  [GOBUSTER CMD]: {' '.join(dirfuzz_fuzzer.get_command())}")
        else:
            print("\n[+] Starting Directory Fuzzing...")
            dirfuzz_results = dirfuzz_fuzzer.run_scan()
            if dirfuzz_results:
                results['directories'] = dirfuzz_results
                print("[+] Directory fuzzing results processed.")

    if 'whatweb' in enabled_modules:
        whatweb_scanner = whatweb.WhatWebScanner(args.target, output_dir)
        if args.no_exec:
            print(f"  [WHATWEB CMD]: {' '.join(whatweb_scanner.get_command())}")
        else:
            print("\n[+] Starting WhatWeb scan...")
            whatweb_results = whatweb_scanner.run_scan()
            if whatweb_results:
                results['whatweb'] = whatweb_results
                print("[+] WhatWeb results processed.")

    if 'nikto' in enabled_modules:
        nikto_scanner = nikto.NiktoScanner(args.target, output_dir)
        if args.no_exec:
            print(f"  [NIKTO CMD]: {' '.join(nikto_scanner.get_command())}")
        else:
            print("\n[+] Starting Nikto scan...")
            nikto_results = nikto_scanner.run_scan()
            if nikto_results:
                results['nikto'] = nikto_results
                print("[+] Nikto results processed.")

    if 'sqlmap' in enabled_modules:
        sqlmap_scanner = sqlmap.SqlmapScanner(args.target, output_dir)
        if args.no_exec:
            print(f"  [SQLMAP CMD]: {' '.join(sqlmap_scanner.get_command())}")
        else:
            print("\n[+] Starting SQLMap scan...")
            sqlmap_results = sqlmap_scanner.run_scan()
            if sqlmap_results:
                results['sqlmap'] = sqlmap_results
                print("[+] SQLMap results processed.")


    print("\n--- Reconnaissance Complete ---")

    if not args.no_exec:
        print("\n[+] Generating reports...")
        output.save_json_output(results, output_dir)
        summary = output.generate_summary(results)
        output.save_text_summary(summary, output_dir)
        print(summary)


if __name__ == '__main__':
    main()
