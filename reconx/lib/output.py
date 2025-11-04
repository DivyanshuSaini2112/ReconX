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

    # URLScan.io results
    if 'urlscan' in data and data.get('urlscan'):
        table = Table(title="URLScan.io Analysis", style="cyan", title_style="bold cyan")
        table.add_column("Category", style="bold magenta")
        table.add_column("Details")

        if 'technologies' in data['urlscan'] and data['urlscan']['technologies']:
            table.add_row("Technologies", ", ".join(data['urlscan']['technologies']))
        if 'ips' in data['urlscan'] and data['urlscan']['ips']:
            table.add_row("IPs", ", ".join(data['urlscan']['ips']))
        if 'domains' in data['urlscan'] and data['urlscan']['domains']:
            table.add_row("Domains", ", ".join(data['urlscan']['domains']))
        if 'network_calls' in data['urlscan'] and data['urlscan']['network_calls']:
            table.add_row("Network Calls", str(len(data['urlscan']['network_calls'])))

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

    if 'urlscan' in data and data.get('urlscan'):
        summary += "## URLScan.io Analysis\n"
        if 'technologies' in data['urlscan'] and data['urlscan']['technologies']:
            summary += f"- Technologies: {', '.join(data['urlscan']['technologies'])}\n"
        if 'ips' in data['urlscan'] and data['urlscan']['ips']:
            summary += f"- IPs: {', '.join(data['urlscan']['ips'])}\n"
        if 'domains' in data['urlscan'] and data['urlscan']['domains']:
            summary += f"- Domains: {', '.join(data['urlscan']['domains'])}\n"
        if 'network_calls' in data['urlscan'] and data['urlscan']['network_calls']:
            summary += f"- Network Calls: {len(data['urlscan']['network_calls'])}\n"
        summary += "\n"

    output_file = os.path.join(output_dir, 'summary.txt')
    try:
        with open(output_file, 'w') as f:
            f.write(summary)
        print(f"[+] Text summary saved to: {output_file}")
    except IOError as e:
        print(f"[!] Error saving text summary: {e}")



def save_html_report(data, output_dir, ai_summary=None):
    """Generates and saves a self-contained HTML report."""

    # Helper to generate a unique ID for a module
    def module_id(name):
        return f"module-{name.lower().replace(' ', '-')}"

    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReconX Report</title>
        <style>
            :root {
                --primary-color: #2c3e50;
                --secondary-color: #3498db;
                --background-color: #ecf0f1;
                --container-bg: #ffffff;
                --text-color: #34495e;
                --header-color: #2c3e50;
                --border-color: #bdc3c7;
                --hover-color: #3498db;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                background-color: var(--background-color);
                color: var(--text-color);
                line-height: 1.6;
            }
            header {
                background-color: var(--primary-color);
                color: white;
                padding: 1.5em;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            nav {
                background: var(--secondary-color);
                padding: 1em;
                position: sticky;
                top: 0;
                z-index: 1000;
            }
            nav ul {
                list-style: none;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                flex-wrap: wrap;
            }
            nav a {
                color: white;
                text-decoration: none;
                padding: 0.5em 1em;
                border-radius: 5px;
                transition: background-color 0.3s;
            }
            nav a:hover {
                background-color: #2980b9;
            }
            .container {
                background: var(--container-bg);
                margin: 2em;
                padding: 2em;
                border-radius: 8px;
                box-shadow: 0 0 15px rgba(0,0,0,0.1);
            }
            .module {
                margin-bottom: 2em;
                padding-top: 60px; /* Offset for sticky nav */
                margin-top: -60px; /* Counteract padding */
            }
            h1, h2 {
                color: var(--header-color);
                border-bottom: 3px solid var(--secondary-color);
                padding-bottom: 8px;
            }
            .code {
                background: #2d2d2d;
                color: #f1f1f1;
                padding: 1em;
                border-radius: 5px;
                font-family: 'Courier New', Courier, monospace;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 1em;
            }
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid var(--border-color);
            }
            th {
                background-color: #eaf2f8;
                font-weight: bold;
            }
            tr:hover { background-color: #f2f2f2; }
            ul { list-style: inside square; padding-left: 0; }
            li { margin-bottom: 0.5em; }
        </style>
    </head>
    <body>
        <header>
            <h1>ReconX Scan Report</h1>
        </header>
    """

    # --- Navigation ---
    nav_links = []
    if ai_summary:
        nav_links.append(f'<li><a href="#{module_id("AI Summary")}">AI Summary</a></li>')
    if 'nmap' in data and data.get('nmap'):
        nav_links.append(f'<li><a href="#{module_id("Nmap")}">Nmap</a></li>')
    if 'urlscan' in data and data.get('urlscan'):
        nav_links.append(f'<li><a href="#{module_id("URLScan")}">URLScan</a></li>')
    if 'subenum' in data and data.get('subenum'):
        nav_links.append(f'<li><a href="#{module_id("Passive Subdomains")}">Passive Subdomains</a></li>')
    if 'subfuzz' in data and data.get('subfuzz'):
        nav_links.append(f'<li><a href="#{module_id("Bruteforce Subdomains")}">Bruteforce Subdomains</a></li>')
    if 'dirfuzz' in data and data.get('dirfuzz'):
        nav_links.append(f'<li><a href="#{module_id("Directories")}">Directories</a></li>')
    if 'whatweb' in data and data.get('whatweb'):
        nav_links.append(f'<li><a href="#{module_id("Web Tech")}">Web Tech</a></li>')

    if nav_links:
        html += "<nav><ul>" + "".join(nav_links) + "</ul></nav>"

    html += '<div class="container">'

    if ai_summary:
        html += f"""
        <div id="{module_id("AI Summary")}" class="module">
            <h2>AI-Powered Summary</h2>
            <div class="code">{ai_summary.replace('\\n', '<br>')}</div>
        </div>
        """

    if 'nmap' in data and data.get('nmap'):
        html += f'<div id="{module_id("Nmap")}" class="module"><h2>Nmap Results</h2>'
        for host in data['nmap']:
            html += f"<h3>Host: {host['ip']}</h3><table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>"
            for port in host['ports']:
                if port['state'] == 'open':
                    service = port.get('service', {})
                    html += f"<tr><td>{port['portid']}</td><td>{port['protocol']}</td><td>{service.get('name', 'N/A')}</td><td>{service.get('product', 'N/A')}</td><td>{service.get('version', 'N/A')}</td></tr>"
            html += "</table>"
        html += '</div>'

    if 'urlscan' in data and data.get('urlscan'):
        html += f'<div id="{module_id("URLScan")}" class="module"><h2>URLScan.io Analysis</h2>'
        if 'technologies' in data['urlscan'] and data['urlscan']['technologies']:
            html += f"<h3>Technologies</h3><ul>{''.join(f'<li>{tech}</li>' for tech in data['urlscan']['technologies'])}</ul>"
        if 'ips' in data['urlscan'] and data['urlscan']['ips']:
            html += f"<h3>IPs</h3><ul>{''.join(f'<li>{ip}</li>' for ip in data['urlscan']['ips'])}</ul>"
        if 'domains' in data['urlscan'] and data['urlscan']['domains']:
            html += f"<h3>Domains</h3><ul>{''.join(f'<li>{domain}</li>' for domain in data['urlscan']['domains'])}</ul>"
        html += '</div>'

    if 'subenum' in data and data.get('subenum'):
        html += f'<div id="{module_id("Passive Subdomains")}" class="module"><h2>Discovered Subdomains (Passive)</h2><ul>'
        for sub in data['subenum']:
            html += f"<li>{sub}</li>"
        html += '</ul></div>'

    if 'subfuzz' in data and data.get('subfuzz'):
        html += f'<div id="{module_id("Bruteforce Subdomains")}" class="module"><h2>Discovered Subdomains (Bruteforce)</h2><ul>'
        for sub in data['subfuzz']:
            html += f"<li>{sub}</li>"
        html += '</ul></div>'

    if 'dirfuzz' in data and data.get('dirfuzz'):
        html += f'<div id="{module_id("Directories")}" class="module"><h2>Discovered Directories</h2><ul>'
        for d in data['dirfuzz']:
            html += f"<li>{d}</li>"
        html += '</ul></div>'

    if 'whatweb' in data and data.get('whatweb'):
        html += f'<div id="{module_id("Web Tech")}" class="module"><h2>Web Technologies</h2>'
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

import groq
from .config import get_api_key

def generate_ai_summary(data):
    """Generates a summary using the Groq API."""
    api_key = get_api_key('GROQ_API_KEY')
    if not api_key:
        return "[bold red]Error: Groq API key not found.[/bold red]"

    client = groq.Groq(api_key=api_key)

    prompt = f"""
    As a senior penetration tester, analyze the following reconnaissance data.
    Correlate the output of all the modules and give possible weak points of the site and entry points for a pentester to exploit.
    Focus on the most critical findings and suggest the top 3-5 immediate next steps.

    Data:
    {json.dumps(data, indent=2)}
    """

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama-3.1-8b-instant",
        )
        return chat_completion.choices[0].message.content.strip()
    except Exception as e:
        return f"[bold red]Error generating AI summary with Groq: {e}[/bold red]"
