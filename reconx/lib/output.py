import json
import os
from rich.table import Table
from rich.console import Group
from rich.text import Text

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
    if data.get('subenum'):
        table = Table(title="Discovered Subdomains (Passive)", style="cyan", title_style="bold cyan")
        table.add_column("Subdomain", style="green")
        for sub in data['subenum']:
            table.add_row(sub)
        renderables.append(table)

    if data.get('lab'):
        table = Table(title="Discovered Subdomains (Lab Mode)", style="cyan", title_style="bold cyan")
        table.add_column("Subdomain", style="green")
        for sub in data['lab']:
            table.add_row(sub)
        renderables.append(table)

    if data.get('subfuzz'):
        table = Table(title="Discovered Subdomains (Bruteforce)", style="cyan", title_style="bold cyan")
        table.add_column("Subdomain", style="green")
        for sub in data['subfuzz']:
            table.add_row(sub)
        renderables.append(table)

    if data.get('dirfuzz'):
        table = Table(title="Interesting Directories", style="cyan", title_style="bold cyan")
        table.add_column("Path", style="green")
        for entry in data['dirfuzz']:
            table.add_row(entry)
        renderables.append(table)

    if data.get('nikto'):
        table = Table(title="Nikto Findings", style="cyan", title_style="bold cyan")
        table.add_column("Finding", style="green")
        for finding in data['nikto']:
            table.add_row(finding)
        renderables.append(table)

    if data.get('sqlmap'):
        sqlmap = data['sqlmap']
        table = Table(title="SQLMap Results", style="cyan", title_style="bold cyan")
        table.add_column("Field", style="magenta")
        table.add_column("Details", style="green")
        table.add_row("Vulnerable", "Yes" if sqlmap.get('vulnerable') else "No")
        if sqlmap.get('vulnerabilities'):
            table.add_row("Parameters", ", ".join(sqlmap['vulnerabilities']))
        if sqlmap.get('db_versions'):
            table.add_row("DBMS", ", ".join(sqlmap['db_versions']))
        renderables.append(table)
        if sqlmap.get('vulnerable'):
            action_list.append("Prioritize exploitation path for SQL injection findings.")

    if data.get('dirfuzz'):
        action_list.append("Review newly discovered directories for sensitive content.")

    if data.get('nikto'):
        action_list.append("Validate Nikto findings and misconfigurations.")

    # Action List
    if action_list:
        table = Table(title="Prioritized Action List", style="yellow", title_style="bold yellow")
        table.add_column("Step", style="magenta")
        table.add_column("Action")
        for i, action in enumerate(action_list[:8], 1):
            table.add_row(str(i), action)
        renderables.append(table)

    return Group(*renderables)

def write_summary_log(data, output_dir):
    """Writes a condensed plaintext summary to scan.log."""
    lines = ["--- ReconX Summary ---", ""]

    if data.get('nmap'):
        lines.append("## Open Ports & Services")
        for host in data['nmap']:
            for port in host['ports']:
                if port['state'] != 'open':
                    continue
                service = port.get('service', {})
                product = service.get('product') or ''
                version = service.get('version') or ''
                service_info = f"{product} {version}".strip()
                lines.append(f"- {host['ip']}:{port['portid']}/{port['protocol']} {service.get('name', 'unknown')} ({service_info})")
        lines.append("")

    for key, heading in (('subenum', 'Passive Subdomains'), ('lab', 'Lab Subdomains'), ('subfuzz', 'Bruteforced Subdomains')):
        if data.get(key):
            lines.append(f"## {heading}")
            for item in data[key]:
                lines.append(f"- {item}")
            lines.append("")

    if data.get('dirfuzz'):
        lines.append("## Discovered Directories")
        for entry in data['dirfuzz']:
            lines.append(f"- {entry}")
        lines.append("")

    if data.get('nikto'):
        lines.append("## Nikto Findings")
        for finding in data['nikto']:
            lines.append(f"- {finding}")
        lines.append("")

    if data.get('urlscan'):
        lines.append("## URLScan.io Highlights")
        urlscan = data['urlscan']
        if urlscan.get('technologies'):
            lines.append(f"- Technologies: {', '.join(urlscan['technologies'])}")
        if urlscan.get('domains'):
            lines.append(f"- Domains: {', '.join(urlscan['domains'])}")
        if urlscan.get('ips'):
            lines.append(f"- IPs: {', '.join(urlscan['ips'])}")
        if urlscan.get('network_calls'):
            lines.append(f"- Network Calls: {len(urlscan['network_calls'])}")
        lines.append("")

    if data.get('sqlmap'):
        lines.append("## SQLMap Status")
        sqlmap = data['sqlmap']
        status = "Vulnerable" if sqlmap.get('vulnerable') else "No injection found"
        lines.append(f"- Status: {status}")
        if sqlmap.get('vulnerabilities'):
            lines.append(f"- Parameters: {', '.join(sqlmap['vulnerabilities'])}")
        if sqlmap.get('db_versions'):
            lines.append(f"- DBMS: {', '.join(sqlmap['db_versions'])}")
        lines.append("")

    errors = _collect_errors(data)
    if errors:
        lines.append("## Module Errors")
        for name, message in errors.items():
            lines.append(f"- {name}: {message}")

    output_file = os.path.join(output_dir, 'scan.log')
    with open(output_file, 'w') as fh:
        fh.write("\n".join(lines).rstrip() + "\n")


def _collect_errors(data):
    errors = {}
    for key, value in data.items():
        if isinstance(value, dict) and value.get('error'):
            errors[key] = value['error']
    return errors

def _escape_html(text):
    """Escape HTML special characters."""
    if not text:
        return ''
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def _module_list(data, key):
    """Return module result as list; if it's an error dict, return []."""
    val = data.get(key)
    if isinstance(val, list):
        return val
    return []

def save_html_report(data, output_dir, ai_summary=None):
    """Generates and saves a professional, interactive HTML dashboard report."""
    
    # Calculate statistics (use _module_list so error dicts don't break counts)
    total_open_ports = 0
    critical_ports = 0
    total_subdomains = len(_module_list(data, 'subenum')) + len(_module_list(data, 'lab')) + len(_module_list(data, 'subfuzz'))
    total_dirs = len(_module_list(data, 'dirfuzz'))
    sql_vulnerable = data.get('sqlmap', {}).get('vulnerable', False)
    
    if 'nmap' in data and data.get('nmap'):
        for host in data['nmap']:
            for port in host['ports']:
                if port['state'] == 'open':
                    total_open_ports += 1
                    if port['portid'] in ['21', '22', '23', '80', '443', '3306', '3389', '8080']:
                        critical_ports += 1
    
    risk_level = "High" if (sql_vulnerable or critical_ports > 3) else ("Medium" if critical_ports > 0 else "Low")
    risk_color = "#ef4444" if risk_level == "High" else ("#f59e0b" if risk_level == "Medium" else "#10b981")
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReconX Security Assessment Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            :root {{
                --bg-primary: #0f172a;
                --bg-secondary: #1e293b;
                --bg-tertiary: #334155;
                --text-primary: #f1f5f9;
                --text-secondary: #cbd5e1;
                --text-muted: #94a3b8;
                --accent-primary: #3b82f6;
                --accent-secondary: #8b5cf6;
                --success: #10b981;
                --warning: #f59e0b;
                --danger: #ef4444;
                --border-color: #334155;
                --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
                --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3);
            }}
            
            body.light-mode {{
                --bg-primary: #f8fafc;
                --bg-secondary: #ffffff;
                --bg-tertiary: #f1f5f9;
                --text-primary: #0f172a;
                --text-secondary: #475569;
                --text-muted: #64748b;
                --border-color: #e2e8f0;
                --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
                --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            }}
            
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
                transition: background-color 0.3s ease, color 0.3s ease;
            }}
            
            .dashboard {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 2rem;
            }}
            
            /* Header */
            .header {{
                background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
                border-radius: 16px;
                padding: 2.5rem;
                margin-bottom: 2rem;
                box-shadow: var(--shadow-lg);
                position: relative;
                overflow: hidden;
            }}
            
            .header::before {{
                content: '';
                position: absolute;
                top: 0;
                right: 0;
                width: 300px;
                height: 300px;
                background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
                border-radius: 50%;
                transform: translate(30%, -30%);
            }}
            
            .header-content {{
                position: relative;
                z-index: 1;
            }}
            
            .header h1 {{
                font-size: 2.5rem;
                font-weight: 700;
                color: white;
                margin-bottom: 0.5rem;
                letter-spacing: -0.5px;
            }}
            
            .header .subtitle {{
                color: rgba(255, 255, 255, 0.9);
                font-size: 1.1rem;
                font-weight: 400;
            }}
            
            .header-actions {{
                position: absolute;
                top: 2rem;
                right: 2rem;
                display: flex;
                gap: 1rem;
                z-index: 2;
            }}
            
            .btn {{
                padding: 0.75rem 1.5rem;
                border: none;
                border-radius: 8px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s ease;
                font-size: 0.9rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }}
            
            .btn-primary {{
                background: rgba(255, 255, 255, 0.2);
                color: white;
                backdrop-filter: blur(10px);
            }}
            
            .btn-primary:hover {{
                background: rgba(255, 255, 255, 0.3);
                transform: translateY(-2px);
            }}
            
            /* Stats Grid */
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}
            
            .stat-card {{
                background: var(--bg-secondary);
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: var(--shadow);
                border: 1px solid var(--border-color);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }}
            
            .stat-card:hover {{
                transform: translateY(-4px);
                box-shadow: var(--shadow-lg);
            }}
            
            .stat-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1rem;
            }}
            
            .stat-label {{
                color: var(--text-muted);
                font-size: 0.875rem;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            .stat-icon {{
                width: 40px;
                height: 40px;
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.2rem;
            }}
            
            .stat-value {{
                font-size: 2.5rem;
                font-weight: 700;
                color: var(--text-primary);
                line-height: 1;
            }}
            
            .stat-change {{
                margin-top: 0.5rem;
                font-size: 0.875rem;
                color: var(--text-muted);
            }}
            
            /* Risk Badge */
            .risk-badge {{
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                border-radius: 20px;
                font-weight: 600;
                font-size: 0.875rem;
                margin-top: 0.5rem;
            }}
            
            .risk-high {{ background: rgba(239, 68, 68, 0.1); color: var(--danger); }}
            .risk-medium {{ background: rgba(245, 158, 11, 0.1); color: var(--warning); }}
            .risk-low {{ background: rgba(16, 185, 129, 0.1); color: var(--success); }}
            
            /* Module Sections */
            .module-section {{
                background: var(--bg-secondary);
                border-radius: 12px;
                padding: 1.5rem;
                margin-bottom: 1.5rem;
                box-shadow: var(--shadow);
                border: 1px solid var(--border-color);
            }}
            
            .module-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
                padding-bottom: 1rem;
                border-bottom: 2px solid var(--border-color);
                cursor: pointer;
                user-select: none;
            }}
            
            .module-title {{
                font-size: 1.5rem;
                font-weight: 600;
                color: var(--text-primary);
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }}
            
            .module-badge {{
                background: var(--accent-primary);
                color: white;
                padding: 0.25rem 0.75rem;
                border-radius: 12px;
                font-size: 0.75rem;
                font-weight: 600;
            }}
            
            .collapse-icon {{
                transition: transform 0.3s ease;
                color: var(--text-muted);
                font-size: 1.5rem;
            }}
            
            .collapsed .collapse-icon {{
                transform: rotate(-90deg);
            }}
            
            .module-content {{
                max-height: 5000px;
                overflow: hidden;
                transition: max-height 0.3s ease, opacity 0.3s ease;
            }}
            
            .collapsed .module-content {{
                max-height: 0;
                opacity: 0;
            }}
            
            /* Tables */
            .data-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                margin-top: 1rem;
            }}
            
            .data-table thead {{
                background: var(--bg-tertiary);
            }}
            
            .data-table th {{
                padding: 1rem;
                text-align: left;
                font-weight: 600;
                color: var(--text-primary);
                font-size: 0.875rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                border-bottom: 2px solid var(--border-color);
            }}
            
            .data-table th:first-child {{
                border-top-left-radius: 8px;
            }}
            
            .data-table th:last-child {{
                border-top-right-radius: 8px;
            }}
            
            .data-table td {{
                padding: 1rem;
                border-bottom: 1px solid var(--border-color);
                color: var(--text-secondary);
            }}
            
            .data-table tbody tr {{
                transition: background-color 0.2s ease;
            }}
            
            .data-table tbody tr:hover {{
                background: var(--bg-tertiary);
            }}
            
            /* Code/Pre blocks */
            .code-block {{
                background: var(--bg-tertiary);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 1.5rem;
                overflow-x: auto;
                font-family: 'Fira Code', 'Courier New', monospace;
                font-size: 0.875rem;
                line-height: 1.6;
                color: var(--text-secondary);
            }}
            
            /* Lists */
            .list-group {{
                list-style: none;
            }}
            
            .list-item {{
                padding: 1rem;
                border-bottom: 1px solid var(--border-color);
                display: flex;
                align-items: center;
                gap: 1rem;
                transition: background-color 0.2s ease;
            }}
            
            .list-item:hover {{
                background: var(--bg-tertiary);
            }}
            
            .list-item:last-child {{
                border-bottom: none;
            }}
            
            .list-bullet {{
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: var(--accent-primary);
                flex-shrink: 0;
            }}
            
            /* Tags */
            .tag {{
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 6px;
                font-size: 0.75rem;
                font-weight: 500;
                margin-right: 0.5rem;
                margin-bottom: 0.5rem;
            }}
            
            .tag-primary {{ background: rgba(59, 130, 246, 0.1); color: var(--accent-primary); }}
            .tag-success {{ background: rgba(16, 185, 129, 0.1); color: var(--success); }}
            .tag-warning {{ background: rgba(245, 158, 11, 0.1); color: var(--warning); }}
            .tag-danger {{ background: rgba(239, 68, 68, 0.1); color: var(--danger); }}
            
            /* Port badge */
            .port-badge {{
                font-family: 'Fira Code', monospace;
                font-weight: 600;
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
                font-size: 0.875rem;
            }}
            
            .port-critical {{
                background: rgba(239, 68, 68, 0.1);
                color: var(--danger);
            }}
            
            .port-normal {{
                background: rgba(59, 130, 246, 0.1);
                color: var(--accent-primary);
            }}
            
            /* Alert boxes */
            .alert {{
                padding: 1.25rem;
                border-radius: 8px;
                margin-bottom: 1.5rem;
                display: flex;
                align-items: flex-start;
                gap: 1rem;
                border-left: 4px solid;
            }}
            
            .alert-info {{
                background: rgba(59, 130, 246, 0.1);
                border-color: var(--accent-primary);
                color: var(--text-primary);
            }}
            
            .alert-warning {{
                background: rgba(245, 158, 11, 0.1);
                border-color: var(--warning);
                color: var(--text-primary);
            }}
            
            .alert-danger {{
                background: rgba(239, 68, 68, 0.1);
                border-color: var(--danger);
                color: var(--text-primary);
            }}
            
            .alert-success {{
                background: rgba(16, 185, 129, 0.1);
                border-color: var(--success);
                color: var(--text-primary);
            }}
            
            /* Footer */
            .footer {{
                text-align: center;
                padding: 2rem;
                color: var(--text-muted);
                font-size: 0.875rem;
                margin-top: 3rem;
            }}
            
            /* Responsive */
            @media (max-width: 768px) {{
                .dashboard {{
                    padding: 1rem;
                }}
                
                .header {{
                    padding: 1.5rem;
                }}
                
                .header h1 {{
                    font-size: 1.75rem;
                }}
                
                .header-actions {{
                    position: static;
                    margin-top: 1rem;
                }}
                
                .stats-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
            
            /* Animations */
            @keyframes fadeIn {{
                from {{
                    opacity: 0;
                    transform: translateY(10px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            
            .module-section {{
                animation: fadeIn 0.5s ease forwards;
            }}
            
            .module-section:nth-child(1) {{ animation-delay: 0.1s; }}
            .module-section:nth-child(2) {{ animation-delay: 0.2s; }}
            .module-section:nth-child(3) {{ animation-delay: 0.3s; }}
            .module-section:nth-child(4) {{ animation-delay: 0.4s; }}
            
            /* Scrollbar */
            ::-webkit-scrollbar {{
                width: 10px;
                height: 10px;
            }}
            
            ::-webkit-scrollbar-track {{
                background: var(--bg-primary);
            }}
            
            ::-webkit-scrollbar-thumb {{
                background: var(--bg-tertiary);
                border-radius: 5px;
            }}
            
            ::-webkit-scrollbar-thumb:hover {{
                background: var(--border-color);
            }}
        </style>
    </head>
    <body>
        <div class="dashboard">
            <!-- Header -->
            <div class="header">
                <div class="header-actions">
                    <button class="btn btn-primary" onclick="toggleTheme()">
                        <span id="theme-icon">🌙</span>
                        <span id="theme-text">Dark Mode</span>
                    </button>
                    <button class="btn btn-primary" onclick="window.print()">
                        📄 Export PDF
                    </button>
                </div>
                <div class="header-content">
                    <h1>🛡️ ReconX Security Assessment</h1>
                    <p class="subtitle">Comprehensive Reconnaissance & Vulnerability Analysis Report</p>
                    <div class="risk-badge risk-{risk_level.lower()}">
                        {'🔴' if risk_level == 'High' else ('🟡' if risk_level == 'Medium' else '🟢')} Risk Level: {risk_level}
                    </div>
                </div>
            </div>
            
            <!-- Statistics Dashboard -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Open Ports</span>
                        <div class="stat-icon" style="background: rgba(59, 130, 246, 0.1); color: var(--accent-primary);">🔌</div>
                    </div>
                    <div class="stat-value">{total_open_ports}</div>
                    <div class="stat-change">{critical_ports} critical services detected</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Subdomains</span>
                        <div class="stat-icon" style="background: rgba(139, 92, 246, 0.1); color: var(--accent-secondary);">🌐</div>
                    </div>
                    <div class="stat-value">{total_subdomains}</div>
                    <div class="stat-change">Total discovered domains</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Directories</span>
                        <div class="stat-icon" style="background: rgba(16, 185, 129, 0.1); color: var(--success);">📁</div>
                    </div>
                    <div class="stat-value">{total_dirs}</div>
                    <div class="stat-change">Enumerated paths</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">SQL Injection</span>
                        <div class="stat-icon" style="background: rgba(239, 68, 68, 0.1); color: var(--danger);">💉</div>
                    </div>
                    <div class="stat-value">{'⚠️' if sql_vulnerable else '✓'}</div>
                    <div class="stat-change">{'Vulnerable!' if sql_vulnerable else 'Not detected'}</div>
                </div>
            </div>
    """

    # AI Summary Section
    if ai_summary:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🤖 AI-Powered Analysis
                        <span class="module-badge">Executive Summary</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <div class="alert alert-info">
                        <span style="font-size: 1.5rem;">ℹ️</span>
                        <div>
                            <strong>Automated Intelligence Summary</strong>
                            <p style="margin-top: 0.5rem; opacity: 0.9;">Generated by AI analysis of all reconnaissance modules</p>
                        </div>
                    </div>
                    <div class="code-block">{_escape_html(ai_summary).replace(chr(10), '<br>')}</div>
                </div>
            </div>
        """

    # Nmap Results
    if 'nmap' in data and data.get('nmap'):
        total_ports = sum(len([p for p in host['ports'] if p['state'] == 'open']) for host in data['nmap'])
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🔍 Network Mapping
                        <span class="module-badge">{total_ports} Open Ports</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
        """
        
        for host in data['nmap']:
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            if open_ports:
                html += f"""
                    <h3 style="color: var(--text-primary); margin: 1.5rem 0 1rem 0; display: flex; align-items: center; gap: 0.5rem;">
                        🖥️ Host: <span style="color: var(--accent-primary);">{_escape_html(host['ip'])}</span>
                    </h3>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Protocol</th>
                                <th>Service</th>
                                <th>Product</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
                """
                
                for port in open_ports:
                    service = port.get('service', {})
                    is_critical = port['portid'] in ['21', '22', '23', '80', '443', '3306', '3389', '8080']
                    port_class = 'port-critical' if is_critical else 'port-normal'
                    
                    html += f"""
                        <tr>
                            <td><span class="port-badge {port_class}">{_escape_html(port['portid'])}</span></td>
                            <td>{_escape_html(port['protocol'])}</td>
                            <td><strong>{_escape_html(service.get('name', 'unknown'))}</strong></td>
                            <td>{_escape_html(service.get('product', 'N/A'))}</td>
                            <td>{_escape_html(service.get('version', 'N/A'))}</td>
                        </tr>
                    """
                
                html += """
                        </tbody>
                    </table>
                """
        
        html += """
                </div>
            </div>
        """

    # WhatWeb Results
    if 'whatweb' in data and data.get('whatweb'):
        tech_count = sum(len(tech.get('plugins', {})) for tech in data['whatweb'])
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🌐 Web Technologies
                        <span class="module-badge">{tech_count} Technologies</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
        """
        
        for tech in data['whatweb']:
            html += f"""
                <h3 style="color: var(--text-primary); margin: 1.5rem 0 1rem 0;">
                    🎯 Target: <span style="color: var(--accent-primary);">{_escape_html(tech.get('target'))}</span>
                </h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Technology</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for plugin, info in tech.get('plugins', {}).items():
                details = []
                if 'version' in info and info['version']:
                    details.append(f"<span class='tag tag-primary'>v{', '.join(map(str, info['version']))}</span>")
                if 'string' in info and info['string']:
                    for s in info['string']:
                        details.append(f"<span class='tag tag-success'>{_escape_html(str(s))}</span>")
                
                html += f"""
                    <tr>
                        <td><strong>{_escape_html(plugin)}</strong></td>
                        <td>{' '.join(details) if details else 'N/A'}</td>
                    </tr>
                """
            
            html += """
                    </tbody>
                </table>
            """
        
        html += """
                </div>
            </div>
        """

    # URLScan.io Results
    if 'urlscan' in data and data.get('urlscan'):
        urlscan = data['urlscan']
        html += """
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🔎 URLScan.io Analysis
                        <span class="module-badge">External Intelligence</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
        """
        
        if urlscan.get('technologies'):
            html += """
                <div style="background: var(--bg-tertiary); padding: 1.5rem; border-radius: 8px;">
                    <h4 style="color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                        ⚙️ Technologies Detected
                    </h4>
                    <div>
            """
            for tech in urlscan['technologies']:
                html += f"<span class='tag tag-primary'>{_escape_html(tech)}</span>"
            html += """
                    </div>
                </div>
            """
        
        if urlscan.get('ips'):
            html += """
                <div style="background: var(--bg-tertiary); padding: 1.5rem; border-radius: 8px;">
                    <h4 style="color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                        🌍 IP Addresses
                    </h4>
                    <ul class="list-group">
            """
            for ip in urlscan['ips']:
                html += f"""
                    <li class="list-item">
                        <span class="list-bullet"></span>
                        <code style="color: var(--accent-primary);">{_escape_html(ip)}</code>
                    </li>
                """
            html += """
                    </ul>
                </div>
            """
        
        if urlscan.get('domains'):
            html += """
                <div style="background: var(--bg-tertiary); padding: 1.5rem; border-radius: 8px;">
                    <h4 style="color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                        🔗 Related Domains
                    </h4>
                    <ul class="list-group">
            """
            for domain in urlscan['domains']:
                html += f"""
                    <li class="list-item">
                        <span class="list-bullet"></span>
                        {_escape_html(domain)}
                    </li>
                """
            html += """
                    </ul>
                </div>
            """
        
        if urlscan.get('network_calls'):
            html += f"""
                <div style="background: var(--bg-tertiary); padding: 1.5rem; border-radius: 8px;">
                    <h4 style="color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                        📡 Network Activity
                    </h4>
                    <div style="font-size: 2rem; font-weight: 700; color: var(--accent-primary);">
                        {len(urlscan['network_calls'])}
                    </div>
                    <div style="color: var(--text-muted); font-size: 0.875rem;">Total network calls detected</div>
                </div>
            """
        
        html += """
                    </div>
                </div>
            </div>
        """

    # Subdomains - Combined
    all_subdomains = []
    for sub in _module_list(data, 'subenum'):
        all_subdomains.append(('Passive', sub))
    for sub in _module_list(data, 'lab'):
        all_subdomains.append(('Lab', sub))
    for sub in _module_list(data, 'subfuzz'):
        all_subdomains.append(('Bruteforce', sub))
    
    if all_subdomains:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🗺️ Subdomain Enumeration
                        <span class="module-badge">{len(all_subdomains)} Discovered</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Method</th>
                                <th>Subdomain</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for method, subdomain in all_subdomains:
            tag_class = 'tag-primary' if method == 'Passive' else ('tag-warning' if method == 'Lab' else 'tag-danger')
            html += f"""
                <tr>
                    <td><span class="tag {tag_class}">{_escape_html(method)}</span></td>
                    <td><code style="color: var(--accent-primary);">{_escape_html(subdomain)}</code></td>
                </tr>
            """
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """

    # Directory Fuzzing
    dirfuzz_list = _module_list(data, 'dirfuzz')
    if dirfuzz_list:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        📂 Directory Discovery
                        <span class="module-badge">{len(dirfuzz_list)} Paths</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <div class="alert alert-warning">
                        <span style="font-size: 1.5rem;">⚠️</span>
                        <div>
                            <strong>Sensitive Paths Detected</strong>
                            <p style="margin-top: 0.5rem; opacity: 0.9;">Review these directories for exposed sensitive information</p>
                        </div>
                    </div>
                    <ul class="list-group">
        """
        
        for entry in dirfuzz_list:
            html += f"""
                <li class="list-item">
                    <span class="list-bullet"></span>
                    <code style="color: var(--accent-primary); font-weight: 500;">{_escape_html(entry)}</code>
                </li>
            """
        
        html += """
                    </ul>
                </div>
            </div>
        """

    # Nikto Findings
    nikto_list = _module_list(data, 'nikto')
    if nikto_list:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🔒 Nikto Security Scan
                        <span class="module-badge">{len(nikto_list)} Findings</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <div class="alert alert-warning">
                        <span style="font-size: 1.5rem;">⚠️</span>
                        <div>
                            <strong>Security Misconfigurations Detected</strong>
                            <p style="margin-top: 0.5rem; opacity: 0.9;">Potential vulnerabilities and server misconfigurations found</p>
                        </div>
                    </div>
                    <ul class="list-group">
        """
        
        for finding in nikto_list:
            html += f"""
                <li class="list-item">
                    <span class="list-bullet" style="background: var(--warning);"></span>
                    <span>{_escape_html(finding)}</span>
                </li>
            """
        
        html += """
                    </ul>
                </div>
            </div>
        """

    # SQLMap Results
    if data.get('sqlmap'):
        sqlmap = data['sqlmap']
        is_vulnerable = sqlmap.get('vulnerable', False)
        alert_class = 'alert-danger' if is_vulnerable else 'alert-success'
        alert_icon = '🚨' if is_vulnerable else '✅'
        status_text = 'SQL Injection Vulnerability Confirmed' if is_vulnerable else 'No SQL Injection Detected'
        
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        💉 SQL Injection Analysis
                        <span class="module-badge">{'VULNERABLE' if is_vulnerable else 'Secure'}</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <div class="alert {alert_class}">
                        <span style="font-size: 1.5rem;">{alert_icon}</span>
                        <div>
                            <strong>{status_text}</strong>
                            <p style="margin-top: 0.5rem; opacity: 0.9;">
                                {'Critical vulnerability requires immediate attention' if is_vulnerable else 'Target appears to be protected against SQL injection'}
                            </p>
                        </div>
                    </div>
        """
        
        if is_vulnerable:
            html += """
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            if sqlmap.get('vulnerabilities'):
                params = ', '.join(sqlmap['vulnerabilities'])
                html += f"""
                    <tr>
                        <td><strong>Vulnerable Parameters</strong></td>
                        <td><span class="tag tag-danger">{_escape_html(params)}</span></td>
                    </tr>
                """
            
            if sqlmap.get('db_versions'):
                dbms = ', '.join(sqlmap['db_versions'])
                html += f"""
                    <tr>
                        <td><strong>Database System</strong></td>
                        <td><span class="tag tag-warning">{_escape_html(dbms)}</span></td>
                    </tr>
                """
            
            html += """
                    </tbody>
                </table>
            """
        
        html += """
                </div>
            </div>
        """

    # Errors Section
    errors = _collect_errors(data)
    if errors:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        ⚠️ Module Errors
                        <span class="module-badge">{len(errors)} Issues</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <div class="alert alert-warning">
                        <span style="font-size: 1.5rem;">⚠️</span>
                        <div>
                            <strong>Some modules encountered errors</strong>
                            <p style="margin-top: 0.5rem; opacity: 0.9;">These modules failed to complete successfully</p>
                        </div>
                    </div>
                    <ul class="list-group">
        """
        
        for module, message in errors.items():
            html += f"""
                <li class="list-item">
                    <span class="list-bullet" style="background: var(--warning);"></span>
                    <div>
                        <strong style="color: var(--text-primary);">{_escape_html(module)}</strong>
                        <div style="color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem;">
                            {_escape_html(message)}
                        </div>
                    </div>
                </li>
            """
        
        html += """
                    </ul>
                </div>
            </div>
        """

    # Footer
    html += """
            <div class="footer">
                <p>🛡️ Generated by ReconX Security Assessment Framework</p>
                <p style="margin-top: 0.5rem; opacity: 0.7;">Professional Penetration Testing & Reconnaissance Tool</p>
            </div>
        </div>
        
        <script>
            // Theme Toggle
            function toggleTheme() {
                const body = document.body;
                const themeIcon = document.getElementById('theme-icon');
                const themeText = document.getElementById('theme-text');
                
                body.classList.toggle('light-mode');
                
                if (body.classList.contains('light-mode')) {
                    themeIcon.textContent = '☀️';
                    themeText.textContent = 'Light Mode';
                    localStorage.setItem('theme', 'light');
                } else {
                    themeIcon.textContent = '🌙';
                    themeText.textContent = 'Dark Mode';
                    localStorage.setItem('theme', 'dark');
                }
            }
            
            // Section Toggle
            function toggleSection(header) {
                const section = header.parentElement;
                section.classList.toggle('collapsed');
            }
            
            // Load saved theme
            document.addEventListener('DOMContentLoaded', function() {
                const savedTheme = localStorage.getItem('theme');
                if (savedTheme === 'light') {
                    document.body.classList.add('light-mode');
                    document.getElementById('theme-icon').textContent = '☀️';
                    document.getElementById('theme-text').textContent = 'Light Mode';
                }
            });
            
            // Expand all sections by default
            document.addEventListener('DOMContentLoaded', function() {
                const sections = document.querySelectorAll('.module-section');
                sections.forEach(section => {
                    section.classList.remove('collapsed');
                });
            });
        </script>
    </body>
    </html>
    """

    output_file = os.path.join(output_dir, 'report.html')
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] Professional HTML dashboard report saved to: {output_file}")
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