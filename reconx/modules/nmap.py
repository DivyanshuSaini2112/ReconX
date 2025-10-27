import subprocess
import xml.etree.ElementTree as ET
import os

class NmapScanner:
    def __init__(self, target, profile, output_dir, nmap_args=''):
        self.target = target
        self.profile = profile
        self.output_dir = output_dir
        self.nmap_args = nmap_args
        self.output_file = os.path.join(self.output_dir, 'nmap_scan.xml')

    def get_command(self):
        base_cmd = f'nmap -oX {self.output_file} {self.target}'

        profile_args = {
            'fast': '-T4 -F -sV --version-light',
            'default': '-T4 -sV -sC',
            'deep': '-T4 -sV -sC -p- -A'
        }

        cmd = f'{base_cmd} {profile_args.get(self.profile, "")}'

        if self.nmap_args:
            cmd += f' {self.nmap_args}'

        return cmd.split()

    def run_scan(self, timeout=None):
        command = self.get_command()
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            return self.parse_results()
        except FileNotFoundError:
            return {'error': "'nmap' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Nmap scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as e:
            return {'error': f"Error running Nmap: {e.stderr}"}

    def parse_results(self):
        try:
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
            print(f"[!] Error parsing Nmap XML output: {e}")
            return None
        except FileNotFoundError:
            print(f"[!] Nmap output file not found: {self.output_file}")
            return None

def run(target, profile, output_dir, nmap_args):
    scanner = NmapScanner(target, profile, output_dir, nmap_args)
    return scanner.run_scan()
