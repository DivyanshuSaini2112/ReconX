import subprocess
import xml.etree.ElementTree as ET
import os
from reconx.lib.utils import run_command_streaming

class NmapScanner:
    def __init__(self, target, profile, output_dir, nmap_args=''):
        self.target = target
        self.profile = profile
        self.output_dir = output_dir
        self.nmap_args = nmap_args
        self.quick_scan_file = os.path.join(self.output_dir, 'nmap_quick_scan.xml')
        self.output_file = os.path.join(self.output_dir, 'nmap_detailed_scan.xml')

    def get_command(self):
        """Returns a descriptive list of commands for no-exec mode."""
        return [
            f"Stage 1 (Port Discovery): nmap -T4 -F -oX {self.quick_scan_file} {self.target}",
            f"Stage 2 (Detailed Scan): nmap -p <open_ports> [profile_args] -oX {self.output_file} {self.target}"
        ]

    def _run_quick_scan(self, timeout, status_callback=None):
        """Runs a fast scan to discover open ports."""
        command = ['nmap', '-T4', '-F', '-oX', self.quick_scan_file, self.target]
        log_file = os.path.join(self.output_dir, 'nmap_quick.log')
        stderr_file = os.path.join(self.output_dir, 'nmap_quick.err')

        if status_callback:
            status_callback("Starting Quick Scan...")

        result = run_command_streaming(command, log_file, stderr_file, status_callback, timeout)

        if result and 'error' in result:
             if "timed out" in result['error']:
                 raise subprocess.TimeoutExpired(command, timeout)
             raise Exception(result['error'])

        return self._parse_open_ports()

    def _parse_open_ports(self):
        """Parses the quick scan XML to find open ports."""
        try:
            tree = ET.parse(self.quick_scan_file)
            root = tree.getroot()
            open_ports = []
            for port in root.findall(".//port"):
                if port.find(".//state[@state='open']") is not None:
                    open_ports.append(port.get('portid'))
            return open_ports
        except (ET.ParseError, FileNotFoundError):
            return []

    def run_scan(self, timeout=None, status_callback=None):
        try:
            # Stage 1: Quick Scan
            open_ports = self._run_quick_scan(timeout, status_callback)

            if not open_ports:
                return {'message': 'No open ports found in the initial scan.'}

            ports_str = ",".join(open_ports)

            # Stage 2: Detailed Scan
            profile_args = {
                'fast': ['-T4', '-sV', '--version-light'],
                'default': ['-T4', '-sV', '-sC'],
                'deep': ['-T4', '-sV', '-sC', '-A']
            }

            base_cmd = ['nmap', '-p', ports_str, '-oX', self.output_file]
            detailed_cmd = base_cmd + profile_args.get(self.profile, [])
            if self.nmap_args:
                detailed_cmd.extend(self.nmap_args.split())
            detailed_cmd.append(self.target)

            log_file = os.path.join(self.output_dir, 'nmap_detailed.log')
            stderr_file = os.path.join(self.output_dir, 'nmap_detailed.err')

            if status_callback:
                status_callback(f"Running Detailed Scan on {len(open_ports)} ports...")

            result = run_command_streaming(detailed_cmd, log_file, stderr_file, status_callback, timeout)

            if result and 'error' in result:
                if "timed out" in result['error']:
                    # Try to parse whatever we have
                    return self.parse_results()
                return result

            return self.parse_results()

        except FileNotFoundError:
            return {'error': "'nmap' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Nmap scan timed out after {timeout} seconds."}
        except Exception as e:
            return {'error': f"Error running Nmap: {str(e)}"}

    def parse_results(self):
        try:
            if not os.path.exists(self.output_file) or os.path.getsize(self.output_file) == 0:
                return None

            tree = ET.parse(self.output_file)
            root = tree.getroot()

            hosts = []
            for host in root.findall('host'):
                host_info = {
                    'ip': host.find('address').get('addr'),
                    'ports': []
                }

                ports = host.find('ports')
                if ports:
                    for port in ports.findall('port'):
                        port_info = {
                            'portid': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': port.find('state').get('state'),
                            'service': {},
                            'scripts': []
                        }

                        service = port.find('service')
                        if service is not None:
                            port_info['service'] = {
                                'name': service.get('name'),
                                'product': service.get('product'),
                                'version': service.get('version')
                            }

                        for script in port.findall('script'):
                            port_info['scripts'].append({
                                'id': script.get('id'),
                                'output': script.get('output')
                            })

                        host_info['ports'].append(port_info)
                hosts.append(host_info)

            return hosts
        except ET.ParseError as e:
            # print(f"[!] Error parsing Nmap XML output: {e}")
            return {'error': f"Error parsing Nmap XML: {e}"}
        except FileNotFoundError:
            # print(f"[!] Nmap output file not found: {self.output_file}")
            return {'error': f"Nmap output file not found: {self.output_file}"}
