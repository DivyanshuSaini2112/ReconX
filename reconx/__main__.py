import argparse
import sys
import os
import datetime
import concurrent.futures
from reconx.modules import nmap, subenum, dirfuzz, whatweb, nikto, sqlmap, ffuf, subfuzz, urlscan, lab
from reconx.lib import output
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

console = Console()

# Wordlists by profile (smaller = faster; fast uses minimal lists to finish in ~5 min)
DIR_WORDLISTS = {
    'fast': '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
    'default': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    'deep': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
}
LAB_WORDLISTS = {
    'fast': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
    'default': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
    'deep': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
}
DEFAULT_DIR_WORDLIST = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
DIR_FAST_FALLBACK = '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt'
DEFAULT_LAB_WORDLIST = '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'

def _get_dir_wordlist(profile):
    path = DIR_WORDLISTS.get(profile, DEFAULT_DIR_WORDLIST)
    if os.path.exists(path):
        return path
    if profile == 'fast' and os.path.exists(DIR_FAST_FALLBACK):
        return DIR_FAST_FALLBACK
    return DEFAULT_DIR_WORDLIST

def _get_lab_wordlist(profile):
    path = LAB_WORDLISTS.get(profile, DEFAULT_LAB_WORDLIST)
    return path if os.path.exists(path) else DEFAULT_LAB_WORDLIST

def run_module(module_name, args, output_dir, timeout):
    """Helper function to run a single scanner module with a timeout."""
    scanner = None
    if module_name == 'nmap':
        scanner = nmap.NmapScanner(args.target, args.profile, output_dir, args.nmap_args)
    elif module_name == 'subenum':
        scanner = subenum.SubdomainScanner(args.target, output_dir)
    elif module_name == 'dirfuzz':
        wordlist = args.wordlist or _get_dir_wordlist(args.profile)
        if args.fuzzer == 'ffuf':
            scanner = ffuf.FfufFuzzer(args.target, wordlist, args.threads, output_dir, args.ffuf_args)
        else:
            scanner = dirfuzz.DirectoryFuzzer(args.target, wordlist, args.threads, output_dir, args.gobuster_args)
    elif module_name == 'whatweb':
        scanner = whatweb.WhatWebScanner(args.target, output_dir)
    elif module_name == 'nikto':
        scanner = nikto.NiktoScanner(args.target, output_dir)
    elif module_name == 'sqlmap':
        scanner = sqlmap.SqlmapScanner(args.target, output_dir)
    elif module_name == 'subfuzz':
        scanner = subfuzz.SubdomainFuzzer(args.target, args.wordlist, args.threads, output_dir, args.ffuf_args)
    elif module_name == 'urlscan':
        scanner = urlscan.UrlScanScanner(args.target, output_dir)
    elif module_name == 'lab':
        wordlist = args.wordlist or _get_lab_wordlist(args.profile)
        scanner = lab.LabSubdomainScanner(args.target, output_dir, wordlist, args.threads, args.gobuster_args)

    if scanner:
        if args.no_exec:
            console.print(f"  [bold cyan]{module_name.upper()} CMD[/bold cyan]: {' '.join(scanner.get_command())}")
            return module_name, None
        else:
            # Pass timeout to the run_scan method
            results = scanner.run_scan(timeout=timeout)
            return module_name, results
    return module_name, None

def main():
    parser = argparse.ArgumentParser(
        description='A CLI-first reconnaissance tool for Kali Linux.',
        epilog='Example: reconx -t example.com --profile default --modules nmap,subenum,dirfuzz,subfuzz --fuzzer ffuf --html --ai-summary'
    )

    # ... (parser arguments are unchanged) ...
    parser.add_argument('-t', '--target', required=True, help='The target IP, domain, or CIDR.')
    parser.add_argument('--modules', default='nmap,subenum,dirfuzz,whatweb,nikto,urlscan', help='Comma-separated list of modules to run (e.g., nmap,subenum,dirfuzz,subfuzz,urlscan).')
    parser.add_argument('--profile', choices=['fast', 'default', 'deep'], default='default', help='Scan profile. Note: fast profile may cause timeouts on some modules.')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads for fuzzing/discovery.')
    parser.add_argument('--wordlist', help='Path to a custom wordlist for directory fuzzing.')
    parser.add_argument('--fuzzer', choices=['gobuster', 'ffuf'], default='gobuster', help='Choose the directory fuzzer to use.')
    parser.add_argument('--out', default='./results', help='Directory to save results to.')
    parser.add_argument('--html', action='store_true', help='Generate an HTML report.')
    parser.add_argument('--lab', action='store_true', help='Use lab-friendly subdomain enumeration (Gobuster DNS).')
    parser.add_argument('--ai-summary', action='store_true', help='Generate a summary using an AI model.')
    parser.add_argument('--nmap-args', help='Custom arguments for Nmap.', default='')
    parser.add_argument('--gobuster-args', help='Custom arguments for Gobuster.', default='')
    parser.add_argument('--ffuf-args', help='Custom arguments for ffuf.', default='')
    parser.add_argument('--sqlmap', action='store_true', help='Explicitly enable the SQLMap module.')
    parser.add_argument('--no-exec', action='store_true', help='Print planned commands without executing them.')

    args = parser.parse_args()

    console.print(Panel.fit("--- ReconX: Automated Reconnaissance Tool ---", style="bold blue"))

    if not args.no_exec:
        console.print("\n[bold yellow]WARNING:[/] This tool is intended for authorized security testing only.")
        console.print("You must have explicit, written permission from the target system's owner.")

        try:
            consent = console.input("\nI confirm I have written authorization to scan this target (type [bold green]YES[/]): ")
            if consent.strip().upper() != 'YES':
                console.print("[bold red]Consent not given. Exiting.[/]")
                sys.exit(0)
        except KeyboardInterrupt:
            console.print("\n[bold red]Scan cancelled by user. Exiting.[/]")
            sys.exit(0)

    console.print(f"\n[+] [bold]Target:[/] {args.target}")
    console.print(f"[+] [bold]Profile:[/] {args.profile}")

    enabled_modules = [m.strip() for m in args.modules.split(',') if m.strip()]
    if args.lab:
        enabled_modules = [m for m in enabled_modules if m != 'subenum']
        if 'lab' not in enabled_modules:
            enabled_modules.append('lab')
    if args.sqlmap:
        enabled_modules.append('sqlmap')
    console.print(f"[+] [bold]Modules:[/] {', '.join(enabled_modules)}")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    target_name = args.target.replace('/', '_')
    output_dir = os.path.join(args.out, f"{target_name}-{timestamp}")
    if not args.no_exec:
        os.makedirs(output_dir, exist_ok=True)
    console.print(f"[+] [bold]Output directory:[/] {output_dir}")

    profile_timeouts = {
        'fast': 300,    # 5 minutes (small wordlists)
        'default': 1800, # 30 minutes
        'deep': 7200     # 2 hours
    }
    timeout = profile_timeouts[args.profile]

    results = {}

    if args.no_exec:
        console.print(Panel.fit("[bold yellow]--- NO-EXEC MODE ---[/]"))
        for module_name in enabled_modules:
            run_module(module_name, args, output_dir, timeout)
    else:
        progress_columns = (
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        )
        with Progress(*progress_columns, console=console, expand=True) as progress:
            tasks = {name: progress.add_task(f"[cyan]Queued {name}...", visible=True) for name in enabled_modules}

            def run_with_progress(name):
                progress.update(tasks[name], description=f"[yellow]Running {name}...")
                return run_module(name, args, output_dir, timeout)

            with concurrent.futures.ThreadPoolExecutor(max_workers=len(enabled_modules)) as executor:
                future_to_module = {executor.submit(run_with_progress, name): name for name in enabled_modules}

                for future in concurrent.futures.as_completed(future_to_module):
                    module_name = future_to_module[future]
                    try:
                        _, module_results = future.result()
                        if module_results:
                            results[module_name] = module_results
                        progress.update(tasks[module_name], completed=100, description=f"[green]Finished {module_name}")
                    except Exception as exc:
                        progress.update(tasks[module_name], description=f"[red]Error in {module_name}")
                        console.print(f"\n[bold red]ERROR[/]: {module_name} generated an exception: {exc}")

    console.print("\n--- Reconnaissance Complete ---")

    if not args.no_exec:
        console.print("\n[+] Generating reports...")
        summary = output.generate_summary(results)
        output.write_summary_log(results, output_dir)

        ai_summary_text = None
        if args.ai_summary:
            ai_summary_text = output.generate_ai_summary(results)
            if ai_summary_text:
                if ai_summary_text.strip().startswith("[bold red]"):
                    console.print(ai_summary_text)
                else:
                    console.print(Panel(Markdown(ai_summary_text), title="AI-Powered Summary", border_style="purple", padding=(1, 2)))

        if args.html:
            output.save_html_report(results, output_dir, ai_summary=ai_summary_text)

        console.print(Panel(summary, title="Initial Attack Vector Summary", border_style="green"))

        console.print("\n[bold yellow]NOTE:[/] If you've made changes to the source code, please run '[bold cyan]pip install .[/]' to apply them.", style="italic")

if __name__ == '__main__':
    main()
