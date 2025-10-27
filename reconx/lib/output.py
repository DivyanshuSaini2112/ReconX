import json
import os
from rich.table import Table
from rich.console import Group
from rich.text import Text

def save_json_output(data, output_dir):
    """Saves the aggregated results to a JSON file."""
    output_file = os.path.join(output_dir, 'reconx_results.json')
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[+] Aggregated JSON results saved to: {output_file}")
    except (IOError, TypeError) as e:
        print(f"[!] Error saving JSON output: {e}")

def generate_summary(data):
    """Generates the Initial Attack Vector Summary using rich Tables."""
    renderables = []
    action_list = []

    # Nmap results
    if 'nmap' in data and data.get('nmap'):
        table = Table(title="Open Ports & Services", style="cyan", title_style="bold cyan")
        table.add_column("Host", style="bold magenta")
        table.add_column("Port", style="yellow")
        table.add_column("Service")
        table.add_column("Version")
        for host in data['nmap']:
            for port in host['ports']:
                if port['state'] == 'open':
                    service = port.get('service', {})
                    product = service.get('product') or ''
                    version = service.get('version') or ''
                    service_info = f"{product} {version}".strip()
                    port_style = "bold red" if port['portid'] in ['80', '443', '8080'] else "yellow"
                    table.add_row(host['ip'], Text(f"{port['portid']}/{port['protocol']}", style=port_style), service.get('name', 'unknown'), service_info)
                    if port['portid'] in ['80', '443', '8080']:
                        action_list.append(f"Investigate web application on port {port['portid']}.")
        renderables.append(table)

    # WhatWeb results
    if 'whatweb' in data and data.get('whatweb'):
        table = Table(title="Web Technologies", style="cyan", title_style="bold cyan")
        table.add_column("Target", style="bold magenta")
        table.add_column("Technology", style="green")
        table.add_column("Details")
        for tech in data['whatweb']:
            for plugin, info in tech.get('plugins', {}).items():
                details = []
                if 'version' in info and info['version']:
                    details.append(f"Version: {', '.join(map(str, info['version']))}")
                if 'string' in info and info['string']:
                    details.append(f"Info: {', '.join(map(str, info['string']))}")
                table.add_row(tech.get('target'), plugin, ' | '.join(details))
        renderables.append(table)

    # Subdomain results
    if 'subenum' in data and data.get('subenum'):
        table = Table(title="Discovered Subdomains (Passive)", style="cyan", title_style="bold cyan")
        table.add_column("Subdomain", style="green")
        for sub in data['subenum']:
            table.add_row(sub)
        renderables.append(table)

    if 'subfuzz' in data and data.get('subfuzz'):
        table = Table(title="Discovered Subdomains (Bruteforce)", style="cyan", title_style="bold cyan")
        table.add_column("Subdomain", style="green")
        for sub in data['subfuzz']:
            table.add_row(sub)
        renderables.append(table)

    # Action List
    if action_list:
        table = Table(title="Prioritized Action List", style="yellow", title_style="bold yellow")
        table.add_column("Step", style="magenta")
        table.add_column("Action")
        for i, action in enumerate(action_list[:8], 1):
            table.add_row(str(i), action)
        renderables.append(table)

    return Group(*renderables)

def save_text_summary(data, output_dir):
    """Saves a plain text summary to a file."""
    summary = "--- Initial Attack Vector Summary ---\n\n"
    # A simplified text version of the rich summary
    if 'nmap' in data and data.get('nmap'):
        summary += "## Open Ports & Services\n"
        for host in data['nmap']:
            for port in host['ports']:
                 if port['state'] == 'open':
                    service = port.get('service', {})
                    product = service.get('product') or ''
                    version = service.get('version') or ''
                    service_info = f"{product} {version}".strip()
                    summary += f"- {host['ip']}:{port['portid']}/{port['protocol']} - {service.get('name', 'unknown')} ({service_info})\n"
        summary += "\n"

    output_file = os.path.join(output_dir, 'summary.txt')
    try:
        with open(output_file, 'w') as f:
            f.write(summary)
        print(f"[+] Text summary saved to: {output_file}")
    except IOError as e:
        print(f"[!] Error saving text summary: {e}")


import ollama

def generate_ai_summary(data):
    """Generates a summary using a local Ollama model."""
    prompt = f"""
    As a senior penetration tester, analyze the following reconnaissance data. Provide a brief, actionable summary for a client.
    Focus on the most critical findings and suggest the top 3-5 immediate next steps.

    Data:
    {json.dumps(data, indent=2)}
    """

    try:
        response = ollama.chat(
            model='llama3',
            messages=[{'role': 'user', 'content': prompt}]
        )
        return response['message']['content'].strip()
    except Exception as e:
        return f"[bold red]Error generating AI summary with Ollama: {e}. Is the Ollama server running?[/bold red]"

def save_html_report(data, output_dir):
    """Generates and saves a self-contained HTML report."""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReconX Report</title>
        <style>
            body { font-family: sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }
            h1, h2, h3 { color: #333; border-bottom: 2px solid #ddd; padding-bottom: 5px; }
            .container { background: #fff; padding: 2em; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            .module { margin-bottom: 2em; }
            .code { background: #eee; padding: 0.5em; border-radius: 3px; font-family: monospace; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ReconX Scan Report</h1>
    """

    if 'nmap' in data and data.get('nmap'):
        html += '<div class="module"><h2>Nmap Results</h2>'
        for host in data['nmap']:
            html += f"<h3>Host: {host['ip']}</h3><table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>"
            for port in host['ports']:
                if port['state'] == 'open':
                    service = port.get('service', {})
                    html += f"<tr><td>{port['portid']}</td><td>{port['protocol']}</td><td>{service.get('name', 'N/A')}</td><td>{service.get('product', 'N/A')}</td><td>{service.get('version', 'N/A')}</td></tr>"
            html += "</table>"
        html += '</div>'

    if 'subenum' in data and data.get('subenum'):
        html += '<div class="module"><h2>Discovered Subdomains (Passive)</h2><ul>'
        for sub in data['subenum']:
            html += f"<li>{sub}</li>"
        html += '</ul></div>'

    if 'subfuzz' in data and data.get('subfuzz'):
        html += '<div class="module"><h2>Discovered Subdomains (Bruteforce)</h2><ul>'
        for sub in data['subfuzz']:
            html += f"<li>{sub}</li>"
        html += '</ul></div>'

    if 'dirfuzz' in data and data.get('dirfuzz'):
        html += '<div class="module"><h2>Discovered Directories</h2><ul>'
        for d in data['dirfuzz']:
            html += f"<li>{d}</li>"
        html += '</ul></div>'

    if 'whatweb' in data and data.get('whatweb'):
        html += '<div class="module"><h2>Web Technologies</h2>'
        for tech in data['whatweb']:
            html += f"<h3>{tech.get('target')}</h3><ul>"
            for plugin, info in tech.get('plugins', {}).items():
                details = []
                if 'version' in info and info['version']:
                    details.append(f"Version: {', '.join(map(str, info['version']))}")
                if 'string' in info and info['string']:
                    details.append(f"Info: {', '.join(map(str, info['string']))}")
                html += f"<li><b>{plugin}:</b> {' | '.join(details)}</li>"
            html += "</ul>"
        html += '</div>'

    html += """
        </div>
    </body>
    </html>
    """

    output_file = os.path.join(output_dir, 'report.html')
    try:
        with open(output_file, 'w') as f:
            f.write(html)
        print(f"[+] HTML report saved to: {output_file}")
    except IOError as e:
        print(f"[!] Error saving HTML report: {e}")
