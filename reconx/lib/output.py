import json
import os

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
    """Generates the Initial Attack Vector Summary."""
    summary = "--- Initial Attack Vector Summary ---\n\n"
    action_list = []

    # Nmap results
    if 'nmap' in data and data['nmap']:
        summary += "## Open Ports & Services\n"
        for host in data['nmap']:
            summary += f"### Host: {host['ip']}\n"
            for port in host['ports']:
                if port['state'] == 'open':
                    service = port.get('service', {})
                    product = service.get('product') or ''
                    version = service.get('version') or ''
                    service_info = f"{product} {version}".strip()
                    summary += f"- **Port {port['portid']}/{port['protocol']}:** {service.get('name', 'unknown')} ({service_info})\n"
                    if port['portid'] in ['80', '443', '8080']:
                        action_list.append(f"Investigate web application on port {port['portid']}.")
                    if 'ssh' in service.get('name', ''):
                        action_list.append(f"Check for weak SSH credentials on port {port['portid']}.")
        summary += "\n"

    # WhatWeb results
    if 'whatweb' in data and data['whatweb']:
        summary += "## Web Technologies\n"
        for tech in data['whatweb']:
            target = tech.get('target', 'Unknown Target')
            summary += f"### Target: {target}\n"
            plugins = tech.get('plugins', {})
            for plugin, info in plugins.items():
                details = []
                if 'version' in info and info['version']:
                    details.append(f"Version: {', '.join(map(str, info['version']))}")
                if 'string' in info and info['string']:
                    details.append(f"Info: {', '.join(map(str, info['string']))}")

                summary += f"- **{plugin}:** {' | '.join(details)}\n"
                if 'version' in info and info['version']:
                    action_list.append(f"Research vulnerabilities for {plugin} version {info['version'][0]}.")
        summary += "\n"

    # Subdomain results
    if 'subdomains' in data:
        summary += "## Discovered Subdomains\n"
        if data['subdomains']:
            for sub in data['subdomains']:
                summary += f"- {sub}\n"
        else:
            summary += "No subdomains found.\n"
        summary += "\n"

    # Directory fuzzing results
    if 'directories' in data:
        summary += "## Interesting Directories/Files\n"
        if data['directories']:
            for directory in data['directories'][:10]:
                summary += f"- {directory}\n"
                if any(admin_path in directory for admin_path in ['/admin', '/dashboard', '/login']):
                     action_list.append(f"Manually investigate sensitive path: {directory}")
            if len(data['directories']) > 10:
                summary += "- ... and more.\n"
        else:
            summary += "No interesting directories found.\n"
        summary += "\n"

    # Nikto findings
    if 'nikto' in data:
        summary += "## Nikto Findings\n"
        if data['nikto']:
            for finding in data['nikto'][:10]:
                summary += f"- {finding}\n"
                if 'OSVDB-3233' in finding: # Apache default file
                    action_list.append("Review Apache default files for information disclosure.")
            if len(data['nikto']) > 10:
                summary += "- ... and more.\n"
        else:
            summary += "No significant findings from Nikto scan.\n"
        summary += "\n"

    # SQLMap results
    if 'sqlmap' in data and data['sqlmap']:
        summary += "## SQL Injection\n"
        if data['sqlmap'].get('vulnerable'):
            summary += "- **Potential SQL injection found!**\n"
            for vuln in data['sqlmap'].get('vulnerabilities', []):
                summary += f"  - {vuln}\n"
            action_list.insert(0, "CRITICAL: Investigate and confirm potential SQL injection.")
        else:
            summary += "- No obvious SQL injection points found with initial scan.\n"
        summary += "\n"


    summary += "## Prioritized Action List\n"
    if action_list:
        for i, action in enumerate(action_list[:8], 1): # Limit to top 8
            summary += f"{i}. {action}\n"
    else:
        summary += "No high-priority actions identified from the automated scan.\n"

    return summary

def save_text_summary(summary, output_dir):
    """Saves the text summary to a file."""
    output_file = os.path.join(output_dir, 'summary.txt')
    try:
        with open(output_file, 'w') as f:
            f.write(summary)
        print(f"[+] Text summary saved to: {output_file}")
    except IOError as e:
        print(f"[!] Error saving text summary: {e}")

import google.generativeai as genai

def generate_ai_summary(data):
    """Generates a summary using the Google Gemini Pro model."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[!] GEMINI_API_KEY environment variable not set. Skipping AI summary.")
        return None

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')

    prompt = f"""
    As a senior penetration tester, analyze the following reconnaissance data. Provide a brief, actionable summary for a client.
    Focus on the most critical findings and suggest the top 3-5 immediate next steps.

    Data:
    {json.dumps(data, indent=2)}
    """

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"[!] Error generating AI summary with Gemini Pro: {e}")
        return None

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

    if 'nmap' in data:
        html += '<div class="module"><h2>Nmap Results</h2>'
        for host in data['nmap']:
            html += f"<h3>Host: {host['ip']}</h3><table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>"
            for port in host['ports']:
                if port['state'] == 'open':
                    service = port.get('service', {})
                    html += f"<tr><td>{port['portid']}</td><td>{port['protocol']}</td><td>{service.get('name', 'N/A')}</td><td>{service.get('product', 'N/A')}</td><td>{service.get('version', 'N/A')}</td></tr>"
            html += "</table>"
        html += '</div>'

    if 'subdomains' in data:
        html += '<div class="module"><h2>Discovered Subdomains</h2><ul>'
        for sub in data['subdomains']:
            html += f"<li>{sub}</li>"
        html += '</ul></div>'

    if 'directories' in data:
        html += '<div class="module"><h2>Discovered Directories</h2><ul>'
        for d in data['directories']:
            html += f"<li>{d}</li>"
        html += '</ul></div>'

    if 'whatweb' in data:
        html += '<div class="module"><h2>Web Technologies</h2>'
        for tech in data['whatweb']:
            html += f"<h3>{tech.get('target')}</h3><ul>"
            for plugin, info in tech.get('plugins', {}).items():
                version = ', '.join(map(str, info.get('version', [])))
                html += f"<li><b>{plugin}:</b> {version}</li>"
            html += "</ul>"
        html += '</div>'

    if 'nikto' in data:
        html += '<div class="module"><h2>Nikto Findings</h2><ul>'
        for finding in data['nikto']:
            html += f"<li>{finding}</li>"
        html += '</ul></div>'

    if 'sqlmap' in data:
        html += '<div class="module"><h2>SQLMap Scan</h2>'
        if data['sqlmap'].get('vulnerable'):
            html += "<p><b>Potential SQL injection found!</b></p><ul>"
            for vuln in data['sqlmap'].get('vulnerabilities', []):
                html += f"<li>{vuln}</li>"
            html += "</ul>"
        else:
            html += "<p>No obvious SQL injection points found.</p>"
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
