import argparse
import asyncio
import datetime
import os
import sys

from rich.console import Console
from rich.panel import Panel

from nexus.graph.build_graph import build_graph
from nexus.graph.state import NEXUSState

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        prog="reconx-agent",
        description="ReconX Agent: autonomous agentic pentesting orchestrator for ReconX.",
        epilog="Example: python -m nexus.main -t example.com --mode standard",
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP, domain, or CIDR.")
    parser.add_argument(
        "--scope",
        help=(
            "Comma-separated list of IPs/CIDRs/domains authorized for testing. "
            "Defaults to just --target if omitted."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["fast", "standard", "deep", "ctf", "bugbounty"],
        default="fast",
        help="Operating mode (Phase 0: only affects the nmap profile used).",
    )
    parser.add_argument("--out", default="./results", help="Directory to save results to.")
    return parser.parse_args()


def confirm_consent() -> bool:
    console.print(
        "\n[bold yellow]WARNING:[/] ReconX Agent performs active reconnaissance and, in later "
        "phases, exploitation. It is intended for authorized security testing only."
    )
    console.print("You must have explicit, written permission from the target system's owner.")
    try:
        consent = console.input(
            "\nI confirm I have written authorization to test this target (type [bold green]YES[/]): "
        )
    except KeyboardInterrupt:
        console.print("\n[bold red]Cancelled by user. Exiting.[/]")
        return False
    return consent.strip().upper() == "YES"


def main():
    args = parse_args()

    console.print(Panel.fit("--- ReconX Agent: Autonomous Pentesting Orchestrator ---", style="bold blue"))

    if not confirm_consent():
        console.print("[bold red]Consent not given. Exiting.[/]")
        sys.exit(0)

    scope = [s.strip() for s in args.scope.split(",")] if args.scope else [args.target]

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    target_name = args.target.replace("/", "_").replace(":", "_")
    output_dir = os.path.join(args.out, f"{target_name}-{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    console.print(f"\n[+] [bold]Target:[/] {args.target}")
    console.print(f"[+] [bold]Scope:[/] {scope}")
    console.print(f"[+] [bold]Mode:[/] {args.mode}")
    console.print(f"[+] [bold]Output directory:[/] {output_dir}")

    initial_state = NEXUSState(
        target=args.target,
        scope=scope,
        mode=args.mode,
        output_dir=output_dir,
        consent_confirmed=True,
    )

    graph = build_graph()

    console.print("\n[+] [bold]Running graph...[/]\n")
    final_state = asyncio.run(graph.ainvoke(initial_state))

    stop_reason = final_state.get("stop_reason")
    if stop_reason and stop_reason.startswith(("SCOPE VIOLATION", "CONSENT")):
        console.print(Panel(stop_reason, title="Aborted", border_style="red"))
        sys.exit(1)

    console.print(Panel(str(stop_reason or "graph reached END"), title="Stop Reason", border_style="cyan"))

    surface = final_state.get("attack_surface")
    if surface:
        console.print(Panel(surface.model_dump_json(indent=2), title="Attack Surface", border_style="green"))

    console.print(Panel(str(final_state.get("agent_statuses")), title="Agent Statuses", border_style="yellow"))
    console.print(f"\n[+] Recon rounds completed: {final_state.get('recon_rounds', 0)}")


if __name__ == "__main__":
    main()
