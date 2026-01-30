import json
import os
from rich.table import Table
from rich.console import Group
from rich.text import Text
import groq
from .config import get_api_key

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

    # Nikto Results
    if 'nikto' in data and data.get('nikto'):
        table = Table(title="Nikto Vulnerabilities", style="red", title_style="bold red")
        table.add_column("Finding", style="white")
        for finding in data['nikto']:
            table.add_row(finding)
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
    """Generates and saves a self-contained, interactive HTML report with a dashboard layout."""

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
                --accent-color: #e74c3c;
                --bg-color: #f4f6f9;
                --text-color: #333;
                --sidebar-width: 250px;
            }
            * { box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: var(--bg-color);
                color: var(--text-color);
                display: flex;
                height: 100vh;
                overflow: hidden;
            }
            /* Sidebar */
            .sidebar {
                width: var(--sidebar-width);
                background-color: var(--primary-color);
                color: #ecf0f1;
                display: flex;
                flex-direction: column;
                padding-top: 20px;
                box-shadow: 2px 0 5px rgba(0,0,0,0.1);
            }
            .sidebar h2 {
                text-align: center;
                margin-bottom: 30px;
                font-size: 1.5em;
                letter-spacing: 1px;
                border-bottom: 1px solid #34495e;
                padding-bottom: 20px;
            }
            .nav-item {
                padding: 15px 20px;
                cursor: pointer;
                transition: background 0.3s;
                font-size: 1.1em;
                border-left: 4px solid transparent;
            }
            .nav-item:hover {
                background-color: #34495e;
            }
            .nav-item.active {
                background-color: #34495e;
                border-left: 4px solid var(--secondary-color);
            }

            /* Main Content */
            .main-content {
                flex: 1;
                padding: 30px;
                overflow-y: auto;
            }
            .section {
                display: none;
                animation: fadeIn 0.5s;
            }
            .section.active {
                display: block;
            }
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            /* Card/Module Styles */
            .card {
                background: #fff;
                padding: 25px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                margin-bottom: 25px;
            }
            h1, h2, h3 { color: var(--primary-color); }
            h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 0; }

            /* Tables */
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
            th { background-color: #f8f9fa; font-weight: 600; color: var(--primary-color); }
            tr:hover { background-color: #f9f9f9; }

            /* Code/Log Blocks */
            .log-block {
                background: #2d3436;
                color: #00cec9;
                padding: 15px;
                border-radius: 5px;
                font-family: 'Consolas', 'Monaco', monospace;
                overflow-x: auto;
                white-space: pre-wrap;
            }
            .finding-low { border-left: 4px solid #2ecc71; padding-left: 10px; }
            .finding-med { border-left: 4px solid #f1c40f; padding-left: 10px; }
            .finding-high { border-left: 4px solid #e74c3c; padding-left: 10px; }

            /* Specific Module Styles */
            .badge {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: bold;
                color: white;
            }
            .badge-port { background-color: var(--secondary-color); }
            .badge-vuln { background-color: var(--accent-color); }

        </style>
    </head>
    <body>
        <div class="sidebar">
            <h2>ReconX</h2>
            <div class="nav-item active" onclick="showSection('overview')">Overview</div>
    """

    # Dynamically build sidebar items based on available data
    if ai_summary:
        html += '<div class="nav-item" onclick="showSection(\'ai-summary\')">AI Summary</div>'
    if 'nmap' in data and data.get('nmap'):
        html += '<div class="nav-item" onclick="showSection(\'nmap\')">Nmap Results</div>'
    if 'dirfuzz' in data and data.get('dirfuzz'):
        html += '<div class="nav-item" onclick="showSection(\'dirfuzz\')">Directory Fuzzing</div>'
    if 'nikto' in data and data.get('nikto'):
        html += '<div class="nav-item" onclick="showSection(\'nikto\')">Nikto Findings</div>'
    if 'subenum' in data and data.get('subenum'):
        html += '<div class="nav-item" onclick="showSection(\'subenum\')">Subdomains</div>'
    if 'subfuzz' in data and data.get('subfuzz'):
        html += '<div class="nav-item" onclick="showSection(\'subfuzz\')">Subdomain Fuzzing</div>'
    if 'whatweb' in data and data.get('whatweb'):
        html += '<div class="nav-item" onclick="showSection(\'whatweb\')">Web Technologies</div>'
    if 'urlscan' in data and data.get('urlscan'):
        html += '<div class="nav-item" onclick="showSection(\'urlscan\')">URLScan.io</div>'

    html += """
        </div>
        <div class="main-content">

            <!-- OVERVIEW SECTION -->
            <div id="overview" class="section active">
                <div class="card">
                    <h1>Scan Overview</h1>
                    <p>Generated by ReconX</p>
                    <p>Select a module from the sidebar to view detailed results.</p>
                </div>
            </div>
    """

    # AI SUMMARY SECTION
    if ai_summary:
        html += f"""
            <div id="ai-summary" class="section">
                <div class="card">
                    <h2>AI-Powered Analysis</h2>
                    <div class="log-block" style="background: #f8f9fa; color: #333; border: 1px solid #ddd;">
                        {ai_summary.replace('\\n', '<br>')}
                    </div>
                </div>
            </div>
        """

    # NMAP SECTION
    if 'nmap' in data and data.get('nmap'):
        html += '<div id="nmap" class="section"><div class="card"><h2>Nmap Port Scan</h2>'
        if isinstance(data['nmap'], dict) and 'error' in data['nmap']:
            html += f'<div style="background: #fee; color: #c0392b; padding: 15px; border-radius: 4px; border-left: 5px solid #c0392b;"><strong>Error:</strong> {data["nmap"]["error"]}</div>'
        else:
            for host in data['nmap']:
                html += f"<h3>Host: {host['ip']}</h3><table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>"
                for port in host['ports']:
                    if port['state'] == 'open':
                        service = port.get('service', {})
                        html += f"<tr><td><span class='badge badge-port'>{port['portid']}</span></td><td>{port['protocol']}</td><td>{service.get('name', 'N/A')}</td><td>{service.get('product', 'N/A')}</td><td>{service.get('version', 'N/A')}</td></tr>"
                html += "</tbody></table>"
        html += '</div></div>'

    # DIRFUZZ SECTION
    if 'dirfuzz' in data and data.get('dirfuzz'):
        html += '<div id="dirfuzz" class="section"><div class="card"><h2>Directory Fuzzing Results</h2>'
        if isinstance(data['dirfuzz'], dict) and 'error' in data['dirfuzz']:
             html += f'<div style="background: #fee; color: #c0392b; padding: 15px; border-radius: 4px; border-left: 5px solid #c0392b;"><strong>Error:</strong> {data["dirfuzz"]["error"]}</div>'
        else:
            html += '<div class="log-block">'
            for d in data['dirfuzz']:
                html += f"<div>{d}</div>"
            html += '</div>'
        html += '</div></div>'

    # NIKTO SECTION
    if 'nikto' in data and data.get('nikto'):
        html += '<div id="nikto" class="section"><div class="card"><h2>Nikto Vulnerability Scan</h2>'
        if isinstance(data['nikto'], dict) and 'error' in data['nikto']:
             html += f'<div style="background: #fee; color: #c0392b; padding: 15px; border-radius: 4px; border-left: 5px solid #c0392b;"><strong>Error:</strong> {data["nikto"]["error"]}</div>'
        else:
            html += '<ul>'
            for finding in data['nikto']:
                html += f"<li style='margin-bottom: 10px;'><span class='finding-high'>{finding}</span></li>"
            html += '</ul>'
        html += '</div></div>'

    # SUBENUM SECTION
    if 'subenum' in data and data.get('subenum'):
        html += '<div id="subenum" class="section"><div class="card"><h2>Discovered Subdomains (Passive)</h2>'
        if isinstance(data['subenum'], dict) and 'error' in data['subenum']:
             html += f'<div style="background: #fee; color: #c0392b; padding: 15px; border-radius: 4px; border-left: 5px solid #c0392b;"><strong>Error:</strong> {data["subenum"]["error"]}</div>'
        else:
            html += '<ul>'
            for sub in data['subenum']:
                html += f"<li><a href='http://{sub}' target='_blank'>{sub}</a></li>"
            html += '</ul>'
        html += '</div></div>'

    # SUBFUZZ SECTION
    if 'subfuzz' in data and data.get('subfuzz'):
        html += '<div id="subfuzz" class="section"><div class="card"><h2>Discovered Subdomains (Bruteforce)</h2>'
        if isinstance(data['subfuzz'], dict) and 'error' in data['subfuzz']:
             html += f'<div style="background: #fee; color: #c0392b; padding: 15px; border-radius: 4px; border-left: 5px solid #c0392b;"><strong>Error:</strong> {data["subfuzz"]["error"]}</div>'
        else:
            html += '<ul>'
            for sub in data['subfuzz']:
                html += f"<li><a href='http://{sub}' target='_blank'>{sub}</a></li>"
            html += '</ul>'
        html += '</div></div>'

    # WHATWEB SECTION
    if 'whatweb' in data and data.get('whatweb'):
        html += '<div id="whatweb" class="section"><div class="card"><h2>Web Technologies</h2>'
        if isinstance(data['whatweb'], dict) and 'error' in data['whatweb']:
             html += f'<div style="background: #fee; color: #c0392b; padding: 15px; border-radius: 4px; border-left: 5px solid #c0392b;"><strong>Error:</strong> {data["whatweb"]["error"]}</div>'
        else:
            for tech in data['whatweb']:
                html += f"<h3>{tech.get('target')}</h3><div style='display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px;'>"
                for plugin, info in tech.get('plugins', {}).items():
                    details = []
                    if 'version' in info and info['version']:
                        details.append(f"v{', '.join(map(str, info['version']))}")
                    details_str = f" ({' '.join(details)})" if details else ""
                    html += f"<div style='background: #eee; padding: 10px; border-radius: 5px;'><b>{plugin}</b>{details_str}</div>"
                html += "</div>"
        html += '</div></div>'

    # URLSCAN SECTION
    if 'urlscan' in data and data.get('urlscan'):
        html += '<div id="urlscan" class="section"><div class="card"><h2>URLScan.io Analysis</h2>'
        if isinstance(data['urlscan'], dict) and 'error' in data['urlscan']:
             html += f'<div style="background: #fee; color: #c0392b; padding: 15px; border-radius: 4px; border-left: 5px solid #c0392b;"><strong>Error:</strong> {data["urlscan"]["error"]}</div>'
        else:
            if 'technologies' in data['urlscan'] and data['urlscan']['technologies']:
                html += f"<h3>Technologies</h3><div style='display: flex; flex-wrap: wrap; gap: 10px;'>{''.join(f'<span class=\"badge\" style=\"background: #555;\">{tech}</span>' for tech in data['urlscan']['technologies'])}</div>"
            if 'ips' in data['urlscan'] and data['urlscan']['ips']:
                html += f"<h3>IPs</h3><ul>{''.join(f'<li>{ip}</li>' for ip in data['urlscan']['ips'])}</ul>"
            if 'domains' in data['urlscan'] and data['urlscan']['domains']:
                html += f"<h3>Related Domains</h3><ul>{''.join(f'<li>{domain}</li>' for domain in data['urlscan']['domains'])}</ul>"
        html += '</div></div>'

    html += """
        </div>
        <script>
            function showSection(sectionId) {
                // Hide all sections
                document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
                // Show target section
                document.getElementById(sectionId).classList.add('active');

                // Update nav state
                document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
                event.target.classList.add('active');
            }
        </script>
    </body>
    </html>
    """

    output_file = os.path.join(output_dir, 'report.html')
    try:
        with open(output_file, 'w') as f:
            f.write(html)
        print(f"[+] Interactive HTML report saved to: {output_file}")
    except IOError as e:
        print(f"[!] Error saving HTML report: {e}")


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
