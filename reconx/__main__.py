import argparse
import sys
import os
import datetime
import concurrent.futures
from reconx.modules import nmap, subenum, dirfuzz, whatweb, nikto, sqlmap, ffuf, subfuzz
from reconx.lib import output
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

console = Console()

def run_module(module_name, args, output_dir, timeout):
    """Helper function to run a single scanner module with a timeout."""
    scanner = None
    if module_name == 'nmap':
        scanner = nmap.NmapScanner(args.target, args.profile, output_dir, args.nmap_args)
    elif module_name == 'subenum':
        scanner = subenum.SubdomainScanner(args.target, output_dir)
    elif module_name == 'dirfuzz':
        if args.fuzzer == 'ffuf':
            scanner = ffuf.FfufFuzzer(args.target, args.wordlist, args.threads, output_dir, args.ffuf_args)
        else:
            scanner = dirfuzz.DirectoryFuzzer(args.target, args.wordlist, args.threads, output_dir, args.gobuster_args)
    elif module_name == 'whatweb':
        scanner = whatweb.WhatWebScanner(args.target, output_dir)
    elif module_name == 'nikto':
        scanner = nikto.NiktoScanner(args.target, output_dir)
    elif module_name == 'sqlmap':
        scanner = sqlmap.SqlmapScanner(args.target, output_dir)
    elif module_name == 'subfuzz':
        scanner = subfuzz.SubdomainFuzzer(args.target, args.wordlist, args.threads, output_dir, args.ffuf_args)

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
    parser.add_argument('--modules', default='nmap,subenum,dirfuzz,whatweb,nikto', help='Comma-separated list of modules to run (e.g., nmap,subenum,dirfuzz,subfuzz).')
    parser.add_argument('--profile', choices=['fast', 'default', 'deep'], default='default', help='Scan profile (fast, default, deep).')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads for fuzzing/discovery.')
    parser.add_argument('--wordlist', help='Path to a custom wordlist for directory fuzzing.')
    parser.add_argument('--fuzzer', choices=['gobuster', 'ffuf'], default='gobuster', help='Choose the directory fuzzer to use.')
    parser.add_argument('--out', default='./results', help='Directory to save results to.')
    parser.add_argument('--html', action='store_true', help='Generate an HTML report.')
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

    enabled_modules = [m.strip() for m in args.modules.split(',')]
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
        'fast': 300,    # 5 minutes
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
        with Progress(console=console) as progress:
            tasks = {name: progress.add_task(f"[cyan]Queued {name}...", visible=True) for name in enabled_modules}
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(enabled_modules)) as executor:
                future_to_module = {executor.submit(run_module, name, args, output_dir, timeout): name for name in enabled_modules}

                for future in concurrent.futures.as_completed(future_to_module):
                    module_name = future_to_module[future]
                    progress.update(tasks[module_name], description=f"[yellow]Running {module_name}...")
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
        output.save_json_output(results, output_dir)
        summary = output.generate_summary(results)
        output.save_text_summary(results, output_dir)
        if args.html:
            output.save_html_report(results, output_dir)

        if args.ai_summary:
            ai_summary = output.generate_ai_summary(results)
            if ai_summary:
                console.print(Panel(ai_summary, title="AI-Powered Summary", border_style="purple"))

        console.print(Panel(summary, title="Initial Attack Vector Summary", border_style="green"))

if __name__ == '__main__':
    main()
