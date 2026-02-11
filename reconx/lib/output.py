import json
import os
import re
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

    if data.get('dirfuzz'):
        table = Table(title="Interesting Directories", style="cyan", title_style="bold cyan")
        table.add_column("Path", style="green")
        for entry in data['dirfuzz']:
            table.add_row(entry)
        renderables.append(table)

    # httpx: list of dicts (url, title, status_code, tech, etc.) or error dict
    if data.get('httpx') and not _is_error(data['httpx']):
        table = Table(title="HTTP Probes (httpx)", style="cyan", title_style="bold cyan")
        table.add_column("URL", style="bold magenta")
        table.add_column("Status", style="yellow")
        table.add_column("Title", style="green")
        table.add_column("Tech", style="cyan")
        for row in _module_list(data, 'httpx'):
            if isinstance(row, dict):
                url = row.get('url') or row.get('input') or row.get('host', '')
                status = str(row.get('status_code') or row.get('status-code', ''))
                title = (row.get('title') or '')[:40]
                t = row.get('tech')
                tech = ', '.join(t[:5]) if isinstance(t, list) else (str(t)[:40] if t else '')
                table.add_row(url, status, title, tech)
        renderables.append(table)

    # nuclei: list of dicts (template-id, info.severity, host, etc.) or error dict
    if data.get('nuclei') and not _is_error(data['nuclei']):
        table = Table(title="Nuclei Findings", style="cyan", title_style="bold cyan")
        table.add_column("Template", style="bold magenta")
        table.add_column("Severity", style="yellow")
        table.add_column("Host", style="green")
        for row in _module_list(data, 'nuclei'):
            if isinstance(row, dict):
                info = row.get('info') or {}
                name = info.get('name') or row.get('template-id') or row.get('templateID') or row.get('template_id') or ''
                severity = info.get('severity') or row.get('severity') or ''
                host = row.get('host') or row.get('matched-at') or row.get('matched_at') or row.get('matchedAt') or ''
                table.add_row(str(name)[:50], str(severity), str(host)[:60])
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

    if data.get('nuclei') and not _is_error(data.get('nuclei')):
        action_list.append("Validate Nuclei findings and prioritize by severity.")

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

    for key, heading in (('subenum', 'Passive Subdomains'), ('lab', 'Lab Subdomains')):
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

    if data.get('httpx') and not _is_error(data.get('httpx')):
        lines.append("## HTTP Probes (httpx)")
        for row in _module_list(data, 'httpx'):
            if isinstance(row, dict):
                url = row.get('url') or row.get('input', '')
                status = row.get('status_code', '')
                title = row.get('title', '')
                lines.append(f"- {url} [{status}] {title}")
        lines.append("")

    if data.get('nuclei') and not _is_error(data.get('nuclei')):
        lines.append("## Nuclei Findings")
        for row in _module_list(data, 'nuclei'):
            if isinstance(row, dict):
                info = row.get('info') or {}
                name = info.get('name') or row.get('template-id') or row.get('templateID', '')
                severity = info.get('severity') or row.get('severity', '')
                host = row.get('host') or row.get('matched-at') or row.get('matched_at', '')
                lines.append(f"- [{severity}] {name} @ {host}")
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

def _is_error(val):
    """True if module returned an error dict."""
    return isinstance(val, dict) and val.get('error') is not None

def _markdown_to_html(text):
    """Convert basic Markdown (**, *, ##, #, newlines) to HTML. Escapes first for safety."""
    if not text:
        return ''
    t = _escape_html(str(text))
    # Headings first (so they get their own lines)
    t = re.sub(r'^### (.+)$', r'<h4 style="color: var(--accent-primary); margin: 1rem 0 0.5rem 0;">\1</h4>', t, flags=re.MULTILINE)
    t = re.sub(r'^## (.+)$', r'<h3 style="color: var(--accent-primary); margin: 1rem 0 0.5rem 0;">\1</h3>', t, flags=re.MULTILINE)
    t = re.sub(r'^# (.+)$', r'<h2 style="color: var(--accent-secondary); margin: 1.25rem 0 0.5rem 0;">\1</h2>', t, flags=re.MULTILINE)
    # Bold **...** (before single * so ** is consumed first)
    t = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', t)
    # Italic *...*
    t = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', t)
    # Newlines to <br>
    t = t.replace('\n', '<br>\n')
    return t

def save_html_report(data, output_dir, ai_summary=None):
    """Generates and saves a professional, highly animated cybersecurity dashboard report with new ReconX logo."""
    
    # Calculate statistics
    total_open_ports = 0
    critical_ports = 0
    total_subdomains = len(_module_list(data, 'subenum')) + len(_module_list(data, 'lab'))
    total_dirs = len(_module_list(data, 'dirfuzz'))
    sql_vulnerable = data.get('sqlmap', {}).get('vulnerable', False)
    
    # Build network topology data for animation
    network_nodes = []
    network_connections = []
    
    if 'nmap' in data and data.get('nmap'):
        for host_idx, host in enumerate(data['nmap']):
            for port in host['ports']:
                if port['state'] == 'open':
                    total_open_ports += 1
                    is_critical = port['portid'] in ['21', '22', '23', '80', '443', '3306', '3389', '8080']
                    if is_critical:
                        critical_ports += 1
                    
                    network_nodes.append({
                        'id': f"host_{host_idx}_port_{port['portid']}",
                        'type': 'port',
                        'label': f"{host['ip']}:{port['portid']}",
                        'critical': is_critical,
                        'service': port.get('service', {}).get('name', 'unknown')
                    })
    
    risk_level = "High" if (sql_vulnerable or critical_ports > 3) else ("Medium" if critical_ports > 0 else "Low")
    risk_color = "#ef4444" if risk_level == "High" else ("#f59e0b" if risk_level == "Medium" else "#10b981")
    
    # Convert network data to JSON
    network_data_json = json.dumps({
        'nodes': network_nodes,
        'connections': network_connections
    })
    
    # NEW RECONX LOGO SVG
    reconx_logo_svg = '''<svg width="120" height="120" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400">
  <defs>
    <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#00F0C3;stop-opacity:1" />
      <stop offset="50%" style="stop-color:#00FFCC;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#00FF88;stop-opacity:1" />
    </linearGradient>
    
    <linearGradient id="grad2" x1="0%" y1="100%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#FFD700;stop-opacity:0.8" />
      <stop offset="100%" style="stop-color:#FFA500;stop-opacity:0.8" />
    </linearGradient>
    
    <filter id="neon">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    
    <radialGradient id="radarGrad">
      <stop offset="0%" style="stop-color:#00F0C3;stop-opacity:0.6" />
      <stop offset="100%" style="stop-color:#00F0C3;stop-opacity:0" />
    </radialGradient>
  </defs>
  
  <rect width="400" height="400" fill="transparent"/>
  
  <g transform="translate(200, 200)">
    
    <circle cx="0" cy="0" r="90" 
            fill="#0F1419" 
            opacity="0.8"/>
    
    <circle cx="0" cy="0" r="85" 
            fill="none" 
            stroke="#00F0C3" 
            stroke-width="1"
            opacity="0.3"/>
    <circle cx="0" cy="0" r="65" 
            fill="none" 
            stroke="#00F0C3" 
            stroke-width="1"
            opacity="0.3"/>
    <circle cx="0" cy="0" r="45" 
            fill="none" 
            stroke="#00F0C3" 
            stroke-width="1"
            opacity="0.3"/>
    <circle cx="0" cy="0" r="25" 
            fill="none" 
            stroke="#00F0C3" 
            stroke-width="1"
            opacity="0.3"/>
    
    <line x1="-85" y1="0" x2="85" y2="0" 
          stroke="#00F0C3" 
          stroke-width="1"
          opacity="0.3"/>
    <line x1="0" y1="-85" x2="0" y2="85" 
          stroke="#00F0C3" 
          stroke-width="1"
          opacity="0.3"/>
    
    <g>
      <path d="M -40,-30 L -40,30 M -40,-30 L -15,-30 Q -5,-30 -5,-20 Q -5,-10 -15,-10 L -40,-10 M -15,-10 L -5,30" 
            stroke="url(#grad1)" 
            stroke-width="5"
            fill="none"
            stroke-linecap="round"
            stroke-linejoin="round"
            filter="url(#neon)"/>
    </g>
    
    <g transform="translate(20, 0)">
      <line x1="-25" y1="-30" x2="25" y2="30" 
            stroke="url(#grad1)" 
            stroke-width="5"
            stroke-linecap="round"
            filter="url(#neon)"/>
      <line x1="25" y1="-30" x2="-25" y2="30" 
            stroke="url(#grad1)" 
            stroke-width="5"
            stroke-linecap="round"
            filter="url(#neon)"/>
    </g>
    
    <circle cx="0" cy="0" r="12" 
            fill="none" 
            stroke="#FFD700" 
            stroke-width="2"
            opacity="0.8"/>
    <circle cx="0" cy="0" r="4" 
            fill="#FFD700" 
            opacity="0.9">
      <animate attributeName="r" values="4;6;4" dur="2s" repeatCount="indefinite"/>
      <animate attributeName="opacity" values="0.9;0.4;0.9" dur="2s" repeatCount="indefinite"/>
    </circle>
    
    <g transform="translate(-65, -65)">
      <line x1="0" y1="0" x2="15" y2="0" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="0" y1="0" x2="0" y2="15" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
    </g>
    
    <g transform="translate(65, -65)">
      <line x1="0" y1="0" x2="-15" y2="0" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="0" y1="0" x2="0" y2="15" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
    </g>
    
    <g transform="translate(-65, 65)">
      <line x1="0" y1="0" x2="15" y2="0" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="0" y1="0" x2="0" y2="-15" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
    </g>
    
    <g transform="translate(65, 65)">
      <line x1="0" y1="0" x2="-15" y2="0" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="0" y1="0" x2="0" y2="-15" stroke="url(#grad1)" stroke-width="2.5" stroke-linecap="round"/>
    </g>
    
    <path d="M 0,-85 A 85,85 0 0,1 60,-60" 
          fill="none" 
          stroke="url(#grad2)" 
          stroke-width="2"
          opacity="0.6"
          filter="url(#neon)">
      <animateTransform
        attributeName="transform"
        type="rotate"
        from="0 0 0"
        to="360 0 0"
        dur="4s"
        repeatCount="indefinite"/>
    </path>
    
    <circle cx="0" cy="0" r="95" 
            fill="none" 
            stroke="url(#grad1)" 
            stroke-width="2.5"
            stroke-dasharray="5 10"
            opacity="0.6"/>
    
    <circle cx="50" cy="-30" r="3" fill="#FFD700">
      <animate attributeName="opacity" values="0;1;0" dur="2s" repeatCount="indefinite"/>
    </circle>
    <circle cx="-40" cy="50" r="3" fill="#00FF88">
      <animate attributeName="opacity" values="1;0;1" dur="2.5s" repeatCount="indefinite"/>
    </circle>
    <circle cx="60" cy="40" r="3" fill="#00F0C3">
      <animate attributeName="opacity" values="0;1;0" dur="1.8s" repeatCount="indefinite" begin="0.5s"/>
    </circle>
    
  </g>
</svg>'''
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReconX - Professional Security Assessment Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            :root {{
                --bg-primary: #0a0e1a;
                --bg-secondary: #0f1419;
                --bg-tertiary: #1a1f2e;
                --bg-card: #141922;
                --text-primary: #e8eaed;
                --text-secondary: #9ca3af;
                --text-muted: #6b7280;
                --accent-primary: #00ff88;
                --accent-secondary: #00d4ff;
                --accent-cyan: #00F0C3;
                --accent-purple: #a78bfa;
                --success: #10b981;
                --warning: #f59e0b;
                --danger: #ef4444;
                --border-color: #1f2937;
                --glow-green: 0 0 20px rgba(0, 255, 136, 0.3);
                --glow-cyan: 0 0 20px rgba(0, 240, 195, 0.4);
                --glow-blue: 0 0 20px rgba(0, 212, 255, 0.3);
                --glow-red: 0 0 20px rgba(239, 68, 68, 0.3);
            }}
            
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
                overflow-x: hidden;
                position: relative;
            }}
            
            /* Animated Background Grid */
            .grid-background {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-image: 
                    linear-gradient(rgba(0, 240, 195, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0, 240, 195, 0.03) 1px, transparent 1px);
                background-size: 50px 50px;
                animation: gridMove 20s linear infinite;
                z-index: 0;
                pointer-events: none;
            }}
            
            @keyframes gridMove {{
                0% {{ background-position: 0 0; }}
                100% {{ background-position: 50px 50px; }}
            }}
            
            /* Particles Container */
            .particles-container {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: 1;
                pointer-events: none;
                overflow: hidden;
            }}
            
            .particle {{
                position: absolute;
                width: 2px;
                height: 2px;
                background: var(--accent-cyan);
                border-radius: 50%;
                opacity: 0;
                animation: particleFloat 15s linear infinite;
            }}
            
            @keyframes particleFloat {{
                0% {{
                    transform: translateY(100vh) translateX(0);
                    opacity: 0;
                }}
                10% {{ opacity: 1; }}
                90% {{ opacity: 1; }}
                100% {{
                    transform: translateY(-100vh) translateX(100px);
                    opacity: 0;
                }}
            }}
            
            /* Neural Network Canvas */
            #network-canvas {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: 1;
                pointer-events: none;
                opacity: 0.35;
            }}
            
            /* Main Container */
            .dashboard {{
                position: relative;
                z-index: 10;
                max-width: 1600px;
                margin: 0 auto;
                padding: 2rem;
            }}
            
            /* Enhanced Header with Logo */
            .header {{
                position: relative;
                background: linear-gradient(135deg, rgba(0, 240, 195, 0.08), rgba(0, 212, 255, 0.08));
                border: 1px solid var(--accent-cyan);
                border-radius: 16px;
                padding: 2.5rem 3rem;
                margin-bottom: 2rem;
                overflow: hidden;
                box-shadow: var(--glow-cyan), 0 10px 40px rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                gap: 2rem;
            }}
            
            .header::before {{
                content: '';
                position: absolute;
                top: -50%;
                right: -50%;
                width: 200%;
                height: 200%;
                background: radial-gradient(circle, rgba(0, 240, 195, 0.1) 0%, transparent 70%);
                animation: headerPulse 8s ease-in-out infinite;
            }}
            
            @keyframes headerPulse {{
                0%, 100% {{ transform: scale(1) rotate(0deg); opacity: 0.5; }}
                50% {{ transform: scale(1.1) rotate(180deg); opacity: 0.8; }}
            }}
            
            .header-logo {{
                position: relative;
                z-index: 3;
                flex-shrink: 0;
                filter: drop-shadow(0 0 15px rgba(0, 240, 195, 0.5));
            }}
            
            .header-content {{
                position: relative;
                z-index: 2;
                flex-grow: 1;
            }}
            
            .header h1 {{
                font-size: 3rem;
                font-weight: 800;
                background: linear-gradient(90deg, var(--accent-cyan), var(--accent-secondary));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 0.5rem;
                letter-spacing: -1px;
                text-shadow: 0 0 30px rgba(0, 240, 195, 0.5);
                animation: textGlow 3s ease-in-out infinite;
            }}
            
            @keyframes textGlow {{
                0%, 100% {{ filter: brightness(1); }}
                50% {{ filter: brightness(1.3); }}
            }}
            
            .header .subtitle {{
                color: var(--text-secondary);
                font-size: 1.1rem;
                font-weight: 400;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .header-actions {{
                position: relative;
                z-index: 3;
                display: flex;
                gap: 1rem;
                flex-shrink: 0;
            }}
            
            .btn {{
                padding: 0.75rem 1.5rem;
                border: 1px solid var(--accent-cyan);
                border-radius: 8px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 0.9rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
                background: rgba(0, 240, 195, 0.05);
                color: var(--accent-cyan);
                font-family: 'JetBrains Mono', monospace;
                position: relative;
                overflow: hidden;
            }}
            
            .btn::before {{
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 0;
                height: 0;
                border-radius: 50%;
                background: rgba(0, 240, 195, 0.2);
                transform: translate(-50%, -50%);
                transition: width 0.5s, height 0.5s;
            }}
            
            .btn:hover::before {{
                width: 300px;
                height: 300px;
            }}
            
            .btn:hover {{
                background: rgba(0, 240, 195, 0.1);
                box-shadow: var(--glow-cyan);
                transform: translateY(-2px);
            }}
            
            .btn span {{
                position: relative;
                z-index: 1;
            }}
            
            /* Holographic Stats Grid */
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}
            
            .stat-card {{
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 1.5rem;
                position: relative;
                overflow: hidden;
                transition: all 0.3s ease;
            }}
            
            .stat-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(0, 240, 195, 0.1), transparent);
                transition: left 0.5s;
            }}
            
            .stat-card:hover::before {{
                left: 100%;
            }}
            
            .stat-card:hover {{
                transform: translateY(-4px);
                border-color: var(--accent-cyan);
                box-shadow: var(--glow-cyan);
            }}
            
            .stat-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1rem;
            }}
            
            .stat-label {{
                color: var(--text-muted);
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .stat-icon {{
                width: 45px;
                height: 45px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.3rem;
                background: rgba(0, 240, 195, 0.1);
                border: 1px solid var(--accent-cyan);
                animation: iconPulse 2s ease-in-out infinite;
            }}
            
            @keyframes iconPulse {{
                0%, 100% {{ transform: scale(1); box-shadow: 0 0 0 0 rgba(0, 240, 195, 0.4); }}
                50% {{ transform: scale(1.05); box-shadow: 0 0 0 10px rgba(0, 240, 195, 0); }}
            }}
            
            .stat-value {{
                font-size: 2.5rem;
                font-weight: 700;
                color: var(--accent-cyan);
                font-family: 'JetBrains Mono', monospace;
                line-height: 1;
                text-shadow: 0 0 20px rgba(0, 240, 195, 0.5);
            }}
            
            .stat-change {{
                margin-top: 0.5rem;
                font-size: 0.875rem;
                color: var(--text-muted);
                font-family: 'JetBrains Mono', monospace;
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
                border: 1px solid;
                animation: riskPulse 2s ease-in-out infinite;
            }}
            
            .risk-high {{ 
                background: rgba(239, 68, 68, 0.1); 
                color: var(--danger); 
                border-color: var(--danger);
                box-shadow: var(--glow-red);
            }}
            .risk-medium {{ 
                background: rgba(245, 158, 11, 0.1); 
                color: var(--warning); 
                border-color: var(--warning);
            }}
            .risk-low {{ 
                background: rgba(16, 185, 129, 0.1); 
                color: var(--success); 
                border-color: var(--success);
            }}
            
            @keyframes riskPulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.7; }}
            }}
            
            /* Module Sections */
            .module-section {{
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 1.5rem;
                margin-bottom: 1.5rem;
                position: relative;
                overflow: hidden;
                transition: all 0.3s ease;
            }}
            
            .module-section::after {{
                content: '';
                position: absolute;
                top: 0;
                right: 0;
                width: 2px;
                height: 100%;
                background: linear-gradient(180deg, transparent, var(--accent-cyan), transparent);
                animation: scanLine 3s linear infinite;
            }}
            
            @keyframes scanLine {{
                0% {{ transform: translateY(-100%); }}
                100% {{ transform: translateY(100%); }}
            }}
            
            .module-section:hover {{
                border-color: var(--accent-cyan);
                box-shadow: var(--glow-cyan);
            }}
            
            .module-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
                padding-bottom: 1rem;
                border-bottom: 1px solid var(--border-color);
                cursor: pointer;
                user-select: none;
            }}
            
            .module-title {{
                font-size: 1.5rem;
                font-weight: 700;
                color: var(--text-primary);
                display: flex;
                align-items: center;
                gap: 0.75rem;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .module-badge {{
                background: linear-gradient(135deg, var(--accent-cyan), var(--accent-secondary));
                color: var(--bg-primary);
                padding: 0.25rem 0.75rem;
                border-radius: 12px;
                font-size: 0.75rem;
                font-weight: 700;
                box-shadow: 0 0 15px rgba(0, 240, 195, 0.5);
            }}
            
            .collapse-icon {{
                transition: transform 0.3s ease;
                color: var(--accent-cyan);
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
            
            /* Futuristic Tables */
            .data-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                margin-top: 1rem;
            }}
            
            .data-table thead {{
                background: linear-gradient(135deg, rgba(0, 240, 195, 0.1), rgba(0, 212, 255, 0.1));
            }}
            
            .data-table th {{
                padding: 1rem;
                text-align: left;
                font-weight: 700;
                color: var(--accent-cyan);
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 1px;
                border-bottom: 2px solid var(--accent-cyan);
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .data-table td {{
                padding: 1rem;
                border-bottom: 1px solid var(--border-color);
                color: var(--text-secondary);
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.875rem;
            }}
            
            .data-table tbody tr {{
                transition: all 0.2s ease;
                position: relative;
            }}
            
            .data-table tbody tr::before {{
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                width: 0;
                height: 100%;
                background: linear-gradient(90deg, var(--accent-cyan), transparent);
                transition: width 0.3s ease;
                opacity: 0.1;
            }}
            
            .data-table tbody tr:hover::before {{
                width: 100%;
            }}
            
            .data-table tbody tr:hover {{
                background: rgba(0, 240, 195, 0.02);
            }}
            
            /* Code Blocks */
            .code-block {{
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-left: 3px solid var(--accent-cyan);
                border-radius: 8px;
                padding: 1.5rem;
                overflow-x: auto;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.875rem;
                line-height: 1.8;
                color: var(--text-secondary);
                position: relative;
            }}
            
            .code-block.ai-summary-html::before {{
                content: '> AI SUMMARY';
            }}
            .code-block::before {{
                content: '> EXECUTION LOG';
                position: absolute;
                top: 0.5rem;
                right: 1rem;
                font-size: 0.65rem;
                color: var(--text-muted);
                opacity: 0.5;
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
                transition: all 0.2s ease;
                position: relative;
            }}
            
            .list-item::before {{
                content: '';
                position: absolute;
                left: 0;
                top: 50%;
                width: 0;
                height: 2px;
                background: var(--accent-cyan);
                transition: width 0.3s ease;
                transform: translateY(-50%);
            }}
            
            .list-item:hover::before {{
                width: 5px;
            }}
            
            .list-item:hover {{
                background: rgba(0, 240, 195, 0.02);
                padding-left: 1.5rem;
            }}
            
            .list-bullet {{
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: var(--accent-cyan);
                flex-shrink: 0;
                box-shadow: 0 0 10px rgba(0, 240, 195, 0.8);
                animation: bulletPulse 2s ease-in-out infinite;
            }}
            
            @keyframes bulletPulse {{
                0%, 100% {{ transform: scale(1); }}
                50% {{ transform: scale(1.2); }}
            }}
            
            /* Tags */
            .tag {{
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 6px;
                font-size: 0.75rem;
                font-weight: 600;
                margin-right: 0.5rem;
                margin-bottom: 0.5rem;
                font-family: 'JetBrains Mono', monospace;
                border: 1px solid;
            }}
            
            .tag-primary {{ 
                background: rgba(0, 212, 255, 0.1); 
                color: var(--accent-secondary); 
                border-color: var(--accent-secondary);
            }}
            .tag-success {{ 
                background: rgba(16, 185, 129, 0.1); 
                color: var(--success); 
                border-color: var(--success);
            }}
            .tag-warning {{ 
                background: rgba(245, 158, 11, 0.1); 
                color: var(--warning); 
                border-color: var(--warning);
            }}
            .tag-danger {{ 
                background: rgba(239, 68, 68, 0.1); 
                color: var(--danger); 
                border-color: var(--danger);
            }}
            
            /* Port Badge */
            .port-badge {{
                font-family: 'JetBrains Mono', monospace;
                font-weight: 700;
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
                font-size: 0.875rem;
                border: 1px solid;
            }}
            
            .port-critical {{
                background: rgba(239, 68, 68, 0.1);
                color: var(--danger);
                border-color: var(--danger);
                box-shadow: 0 0 10px rgba(239, 68, 68, 0.3);
            }}
            
            .port-normal {{
                background: rgba(0, 240, 195, 0.1);
                color: var(--accent-cyan);
                border-color: var(--accent-cyan);
            }}
            
            /* Alert Boxes */
            .alert {{
                padding: 1.25rem;
                border-radius: 8px;
                margin-bottom: 1.5rem;
                display: flex;
                align-items: flex-start;
                gap: 1rem;
                border-left: 4px solid;
                position: relative;
                overflow: hidden;
            }}
            
            .alert::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: linear-gradient(45deg, transparent 30%, rgba(255, 255, 255, 0.05) 50%, transparent 70%);
                animation: alertShimmer 3s linear infinite;
            }}
            
            @keyframes alertShimmer {{
                0% {{ transform: translateX(-100%); }}
                100% {{ transform: translateX(100%); }}
            }}
            
            .alert-info {{
                background: rgba(0, 212, 255, 0.05);
                border-color: var(--accent-secondary);
            }}
            
            .alert-warning {{
                background: rgba(245, 158, 11, 0.05);
                border-color: var(--warning);
            }}
            
            .alert-danger {{
                background: rgba(239, 68, 68, 0.05);
                border-color: var(--danger);
            }}
            
            .alert-success {{
                background: rgba(16, 185, 129, 0.05);
                border-color: var(--success);
            }}
            
            /* Terminal-style time display */
            .terminal-time {{
                position: fixed;
                top: 1rem;
                left: 1rem;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.75rem;
                color: var(--accent-cyan);
                background: rgba(0, 0, 0, 0.5);
                padding: 0.5rem 1rem;
                border-radius: 6px;
                border: 1px solid var(--accent-cyan);
                z-index: 1000;
                box-shadow: var(--glow-cyan);
            }}
            
            /* Loading Bar Animation */
            .loading-bar {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 3px;
                background: var(--accent-cyan);
                transform-origin: left;
                animation: loadingProgress 2s ease-in-out infinite;
                z-index: 9999;
                box-shadow: 0 0 10px var(--accent-cyan);
            }}
            
            @keyframes loadingProgress {{
                0% {{ transform: scaleX(0); }}
                50% {{ transform: scaleX(0.7); }}
                100% {{ transform: scaleX(1); }}
            }}
            
            /* Footer */
            .footer {{
                text-align: center;
                padding: 2rem;
                color: var(--text-muted);
                font-size: 0.875rem;
                margin-top: 3rem;
                font-family: 'JetBrains Mono', monospace;
                border-top: 1px solid var(--border-color);
            }}
            
            /* Responsive */
            @media (max-width: 768px) {{
                .dashboard {{ padding: 1rem; }}
                .header {{ 
                    padding: 1.5rem; 
                    flex-direction: column;
                }}
                .header h1 {{ font-size: 2rem; }}
                .header-actions {{
                    margin-top: 1rem;
                    flex-direction: column;
                    width: 100%;
                }}
                .header-logo {{
                    margin: 0 auto;
                }}
                .stats-grid {{ grid-template-columns: 1fr; }}
            }}
            
            /* Scrollbar */
            ::-webkit-scrollbar {{ width: 10px; height: 10px; }}
            ::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
            ::-webkit-scrollbar-thumb {{ 
                background: var(--accent-cyan); 
                border-radius: 5px;
                box-shadow: 0 0 10px var(--accent-cyan);
            }}
            ::-webkit-scrollbar-thumb:hover {{ 
                background: var(--accent-secondary); 
            }}
        </style>
    </head>
    <body>
        <!-- Loading Bar -->
        <div class="loading-bar"></div>
        
        <!-- Terminal Time Display -->
        <div class="terminal-time">
            <span id="current-time"></span>
        </div>
        
        <!-- Animated Background Grid -->
        <div class="grid-background"></div>
        
        <!-- Particles Container -->
        <div class="particles-container" id="particles"></div>
        
        <!-- Neural Network Canvas -->
        <canvas id="network-canvas"></canvas>
        
        <div class="dashboard">
            <!-- Header with Logo -->
            <div class="header">
                <div class="header-logo">
                    {reconx_logo_svg}
                </div>
                <div class="header-content">
                    <h1>RECONX SECURITY PLATFORM</h1>
                    <p class="subtitle">&gt; COMPREHENSIVE RECONNAISSANCE & VULNERABILITY ANALYSIS SYSTEM</p>
                    <div class="risk-badge risk-{risk_level.lower()}">
                        {'🔴' if risk_level == 'High' else ('🟡' if risk_level == 'Medium' else '🟢')} THREAT LEVEL: {risk_level.upper()}
                    </div>
                </div>
                <div class="header-actions">
                    <button class="btn" onclick="window.print()">
                        <span>📄</span>
                        <span>EXPORT PDF</span>
                    </button>
                    <button class="btn" onclick="toggleFullscreen()">
                        <span>⛶</span>
                        <span>FULLSCREEN</span>
                    </button>
                </div>
            </div>
            
            <!-- Statistics Dashboard -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">OPEN PORTS</span>
                        <div class="stat-icon">🔌</div>
                    </div>
                    <div class="stat-value">{total_open_ports}</div>
                    <div class="stat-change">> {critical_ports} critical services detected</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">SUBDOMAINS</span>
                        <div class="stat-icon">🌐</div>
                    </div>
                    <div class="stat-value">{total_subdomains}</div>
                    <div class="stat-change">> total enumerated domains</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">DIRECTORIES</span>
                        <div class="stat-icon">📁</div>
                    </div>
                    <div class="stat-value">{total_dirs}</div>
                    <div class="stat-change">> discovered paths</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">SQL INJECTION</span>
                        <div class="stat-icon">💉</div>
                    </div>
                    <div class="stat-value">{'⚠' if sql_vulnerable else '✓'}</div>
                    <div class="stat-change">{'> VULNERABILITY CONFIRMED' if sql_vulnerable else '> not detected'}</div>
                </div>
            </div>
    """

    # AI Summary Section
    if ai_summary:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🤖 AI-POWERED ANALYSIS
                        <span class="module-badge">EXECUTIVE SUMMARY</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <div class="alert alert-info">
                        <span style="font-size: 1.5rem;">ℹ️</span>
                        <div>
                            <strong>Automated Intelligence Summary</strong>
                            <p style="margin-top: 0.5rem; opacity: 0.9;">> Generated by advanced AI analysis of all reconnaissance modules</p>
                        </div>
                    </div>
                    <div class="code-block ai-summary-html">{_markdown_to_html(ai_summary)}</div>
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
                        🔍 NETWORK MAPPING
                        <span class="module-badge">{total_ports} OPEN PORTS</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
        """
        
        for host in data['nmap']:
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            if open_ports:
                html += f"""
                    <h3 style="color: var(--accent-cyan); margin: 1.5rem 0 1rem 0; display: flex; align-items: center; gap: 0.5rem; font-family: 'JetBrains Mono', monospace;">
                        🖥️ HOST: <span style="color: var(--accent-secondary);">{_escape_html(host['ip'])}</span>
                    </h3>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>PORT</th>
                                <th>PROTOCOL</th>
                                <th>SERVICE</th>
                                <th>PRODUCT</th>
                                <th>VERSION</th>
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

    # Subdomains (subenum + lab)
    subenum_list = _module_list(data, 'subenum')
    lab_list = _module_list(data, 'lab')
    if subenum_list or lab_list:
        all_subs = list(subenum_list) + list(lab_list)
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🌐 SUBDOMAINS
                        <span class="module-badge">{len(all_subs)} DISCOVERED</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>SUBDOMAIN</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        for sub in all_subs[:200]:
            html += f"""
                        <tr>
                            <td><code>{_escape_html(str(sub))}</code></td>
                        </tr>
            """
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """

    # Discovered directories (dirfuzz)
    dirfuzz_list = _module_list(data, 'dirfuzz')
    if dirfuzz_list:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        📁 DISCOVERED DIRECTORIES
                        <span class="module-badge">{len(dirfuzz_list)} PATHS</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>PATH</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        for entry in dirfuzz_list[:200]:
            html += f"""
                        <tr>
                            <td><code>{_escape_html(str(entry))}</code></td>
                        </tr>
            """
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """

    # WhatWeb
    if data.get('whatweb') and not _is_error(data.get('whatweb')) and _module_list(data, 'whatweb'):
        ww_list = _module_list(data, 'whatweb')
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🔧 WEB TECHNOLOGIES (WHATWEB)
                        <span class="module-badge">{len(ww_list)} TARGETS</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>TARGET</th>
                                <th>PLUGIN</th>
                                <th>DETAILS</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        for tech in ww_list:
            if isinstance(tech, dict):
                target = _escape_html(tech.get('target', ''))
                for plugin, info in (tech.get('plugins') or {}).items():
                    details = []
                    if isinstance(info, dict):
                        if info.get('version'):
                            details.append('Version: ' + ', '.join(map(str, info['version'])))
                        if info.get('string'):
                            details.append('Info: ' + ', '.join(map(str, info['string'])))
                    details_str = _escape_html(' | '.join(details)[:80])
                    html += f"""
                        <tr>
                            <td><code>{target}</code></td>
                            <td><strong>{_escape_html(plugin)}</strong></td>
                            <td>{details_str}</td>
                        </tr>
                    """
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """

    # URLScan.io
    if data.get('urlscan') and not _is_error(data.get('urlscan')):
        us = data['urlscan']
        html += """
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🔗 URLSCAN.IO ANALYSIS
                        <span class="module-badge">EXTERNAL SCAN</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>CATEGORY</th>
                                <th>DETAILS</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        if us.get('technologies'):
            html += f"""
                        <tr>
                            <td><strong>Technologies</strong></td>
                            <td>{_escape_html(', '.join(us['technologies']))}</td>
                        </tr>
            """
        if us.get('domains'):
            html += f"""
                        <tr>
                            <td><strong>Domains</strong></td>
                            <td>{_escape_html(', '.join(us['domains'][:30]))}</td>
                        </tr>
            """
        if us.get('ips'):
            html += f"""
                        <tr>
                            <td><strong>IPs</strong></td>
                            <td>{_escape_html(', '.join(us['ips'][:20]))}</td>
                        </tr>
            """
        if us.get('network_calls'):
            html += f"""
                        <tr>
                            <td><strong>Network Calls</strong></td>
                            <td>{len(us['network_calls'])}</td>
                        </tr>
            """
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """

    # HTTP Probes (httpx)
    httpx_list = _module_list(data, 'httpx') if data.get('httpx') and not _is_error(data.get('httpx')) else []
    if httpx_list:
        html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🌐 HTTP PROBES (HTTPX)
                        <span class="module-badge">{len(httpx_list)} HOSTS</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>STATUS</th>
                                <th>TITLE</th>
                                <th>TECH</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        for row in httpx_list[:50]:
            if isinstance(row, dict):
                url = _escape_html(row.get('url') or row.get('input') or row.get('host', ''))
                status = _escape_html(str(row.get('status_code') or row.get('status-code', '')))
                title = _escape_html((row.get('title') or '')[:60])
                t = row.get('tech')
                tech = ', '.join(t[:5]) if isinstance(t, list) else _escape_html(str(t or '')[:40])
                html += f"""
                        <tr>
                            <td><code>{url}</code></td>
                            <td>{status}</td>
                            <td>{title}</td>
                            <td>{tech}</td>
                        </tr>
                """
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """

    # Nuclei findings (show section even when 0 findings so user sees nuclei ran)
    nuclei_list = _module_list(data, 'nuclei') if data.get('nuclei') and not _is_error(data.get('nuclei')) else []
    nuclei_err = data.get('nuclei') if _is_error(data.get('nuclei')) else None
    html += f"""
            <div class="module-section">
                <div class="module-header" onclick="toggleSection(this)">
                    <div class="module-title">
                        🎯 NUCLEI
                        <span class="module-badge">{len(nuclei_list)} FINDINGS</span>
                    </div>
                    <span class="collapse-icon">▼</span>
                </div>
                <div class="module-content">
    """
    if nuclei_err:
        html += f"""
                    <div class="alert alert-info">
                        <strong>Nuclei run note:</strong> {_escape_html(nuclei_err.get('error', 'Unknown error'))}
                    </div>
        """
    elif nuclei_list:
        html += """
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>TEMPLATE</th>
                                <th>SEVERITY</th>
                                <th>HOST</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        for row in nuclei_list[:100]:
            if isinstance(row, dict):
                info = row.get('info') or {}
                name = _escape_html(info.get('name') or row.get('template-id') or row.get('templateID', ''))
                severity = info.get('severity') or row.get('severity', '')
                sev_class = 'port-critical' if severity in ('critical', 'high') else 'port-normal'
                host = _escape_html(str(row.get('host') or row.get('matched-at') or row.get('matched_at', ''))[:80])
                html += f"""
                        <tr>
                            <td><strong>{name}</strong></td>
                            <td><span class="port-badge {sev_class}">{_escape_html(severity)}</span></td>
                            <td><code>{host}</code></td>
                        </tr>
                """
        html += """
                        </tbody>
                    </table>
        """
    else:
        html += """
                    <div class="alert alert-info">
                        Nuclei ran successfully; no template findings for this target/severity. Check <code>nuclei.log</code> in the results folder for full output.
                    </div>
        """
    html += """
                </div>
            </div>
    """

    html += f"""
            <div class="footer">
                <p>⚡ POWERED BY RECONX SECURITY ASSESSMENT FRAMEWORK</p>
                <p style="margin-top: 0.5rem; opacity: 0.7;">> Professional Penetration Testing & Reconnaissance Platform</p>
            </div>
        </div>
        
        <script>
            // Neural Network Animation
            const canvas = document.getElementById('network-canvas');
            const ctx = canvas.getContext('2d');
            
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            
            window.addEventListener('resize', () => {{
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            }});
            
            // Network data from Python
            const networkData = {network_data_json};
            
            class Node {{
                constructor(x, y, data) {{
                    this.x = x;
                    this.y = y;
                    this.vx = (Math.random() - 0.5) * 0.5;
                    this.vy = (Math.random() - 0.5) * 0.5;
                    this.data = data;
                    this.connections = [];
                    this.pulsePhase = Math.random() * Math.PI * 2;
                }}
                
                update() {{
                    this.x += this.vx;
                    this.y += this.vy;
                    
                    // Bounce off edges
                    if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
                    if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
                    
                    // Keep in bounds
                    this.x = Math.max(0, Math.min(canvas.width, this.x));
                    this.y = Math.max(0, Math.min(canvas.height, this.y));
                    
                    this.pulsePhase += 0.05;
                }}
                
                draw() {{
                    const pulse = Math.sin(this.pulsePhase) * 0.5 + 0.5;
                    const size = 3 + pulse * 2;
                    const opacity = 0.6 + pulse * 0.4;
                    
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, size, 0, Math.PI * 2);
                    ctx.fillStyle = this.data.critical ? 
                        `rgba(239, 68, 68, ${{opacity}})` : 
                        `rgba(0, 240, 195, ${{opacity}})`;
                    ctx.fill();
                    
                    // Glow effect
                    ctx.shadowBlur = 15;
                    ctx.shadowColor = this.data.critical ? '#ef4444' : '#00F0C3';
                    ctx.fill();
                    ctx.shadowBlur = 0;
                }}
            }}
            
            // Create nodes
            const nodes = [];
            const maxNodes = Math.min(networkData.nodes.length + 20, 50);
            
            for (let i = 0; i < maxNodes; i++) {{
                const nodeData = networkData.nodes[i] || {{ critical: Math.random() > 0.7 }};
                nodes.push(new Node(
                    Math.random() * canvas.width,
                    Math.random() * canvas.height,
                    nodeData
                ));
            }}
            
            function drawConnections() {{
                for (let i = 0; i < nodes.length; i++) {{
                    for (let j = i + 1; j < nodes.length; j++) {{
                        const dx = nodes[i].x - nodes[j].x;
                        const dy = nodes[i].y - nodes[j].y;
                        const distance = Math.sqrt(dx * dx + dy * dy);
                        
                        if (distance < 150) {{
                            const opacity = (1 - distance / 150) * 0.3;
                            ctx.beginPath();
                            ctx.moveTo(nodes[i].x, nodes[i].y);
                            ctx.lineTo(nodes[j].x, nodes[j].y);
                            ctx.strokeStyle = `rgba(0, 240, 195, ${{opacity}})`;
                            ctx.lineWidth = 0.5;
                            ctx.stroke();
                        }}
                    }}
                }}
            }}
            
            function animate() {{
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                
                drawConnections();
                
                nodes.forEach(node => {{
                    node.update();
                    node.draw();
                }});
                
                requestAnimationFrame(animate);
            }}
            
            animate();
            
            // Create particles
            function createParticles() {{
                const container = document.getElementById('particles');
                for (let i = 0; i < 30; i++) {{
                    const particle = document.createElement('div');
                    particle.className = 'particle';
                    particle.style.left = Math.random() * 100 + '%';
                    particle.style.animationDelay = Math.random() * 15 + 's';
                    particle.style.animationDuration = (15 + Math.random() * 10) + 's';
                    container.appendChild(particle);
                }}
            }}
            
            createParticles();
            
            // Terminal time display
            function updateTime() {{
                const now = new Date();
                const timeStr = now.toISOString().replace('T', ' ').substr(0, 19);
                document.getElementById('current-time').textContent = `> ${{timeStr}} UTC`;
            }}
            
            updateTime();
            setInterval(updateTime, 1000);
            
            // Section toggle
            function toggleSection(header) {{
                const section = header.parentElement;
                section.classList.toggle('collapsed');
            }}
            
            // Fullscreen toggle
            function toggleFullscreen() {{
                if (!document.fullscreenElement) {{
                    document.documentElement.requestFullscreen();
                }} else {{
                    document.exitFullscreen();
                }}
            }}
            
            // Remove loading bar after page load
            window.addEventListener('load', () => {{
                setTimeout(() => {{
                    const loadingBar = document.querySelector('.loading-bar');
                    if (loadingBar) {{
                        loadingBar.style.opacity = '0';
                        setTimeout(() => loadingBar.remove(), 500);
                    }}
                }}, 2000);
            }});
        </script>
    </body>
    </html>
    """

    output_file = os.path.join(output_dir, 'report.html')
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] Professional animated HTML dashboard saved to: {output_file}")
    except IOError as e:
        print(f"[!] Error saving HTML report: {e}")

# Keep the existing AI summary function
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
        return f"[bold red]Error generating AI summary with Groq: {e}[/bold red]"# type: ignore
