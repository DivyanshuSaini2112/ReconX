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
                    product = service.get('product', '')
                    version = service.get('version', '')
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
                version = ', '.join(map(str, info.get('version', [])))
                summary += f"- **{plugin}:** {version}\n"
                if version:
                    action_list.append(f"Research vulnerabilities for {plugin} version {version}.")
        summary += "\n"

    # Directory fuzzing results
    if 'directories' in data and data['directories']:
        summary += "## Interesting Directories/Files\n"
        for directory in data['directories'][:10]:
            summary += f"- {directory}\n"
            if any(admin_path in directory for admin_path in ['/admin', '/dashboard', '/login']):
                 action_list.append(f"Manually investigate sensitive path: {directory}")
        if len(data['directories']) > 10:
            summary += "- ... and more.\n"
        summary += "\n"

    # Nikto findings
    if 'nikto' in data and data['nikto']:
        summary += "## Nikto Findings\n"
        for finding in data['nikto'][:10]:
            summary += f"- {finding}\n"
            if 'OSVDB-3233' in finding: # Apache default file
                action_list.append("Review Apache default files for information disclosure.")
        if len(data['nikto']) > 10:
            summary += "- ... and more.\n"
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
