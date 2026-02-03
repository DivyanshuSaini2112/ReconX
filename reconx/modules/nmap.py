import os
import shlex
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Union


class NmapScanner:
    def __init__(self, target: str, profile: str, output_dir: str, nmap_args: str = ''):
        self.target = target
        self.profile = profile
        self.output_dir = output_dir
        self.nmap_args = nmap_args or ''
        self.log_file = os.path.join(self.output_dir, 'nmap.log')

    def get_command(self) -> List[str]:
        """Returns a descriptive list of commands for no-exec mode."""
        quick = "nmap -T4 -F -oX - {target}".format(target=self.target)
        detailed = "nmap -p <open_ports> {profile} {extra} -oX - {target}".format(
            profile=" ".join(self._profile_args()),
            extra=self.nmap_args,
            target=self.target
        ).strip()
        return [
            f"Stage 1 (Port Discovery): {quick}",
            f"Stage 2 (Detailed Scan): {detailed}"
        ]

    def run_scan(self, timeout: Optional[int] = None) -> Union[List[Dict], dict]:
        try:
            quick_cmd = ['nmap', '-T4', '-F', '-oX', '-', self.target]
            quick_result = self._run_command(quick_cmd, timeout, stage='quick')
            open_ports = self._parse_open_ports(quick_result.stdout)

            if not open_ports:
                return {'message': 'No open ports found in the initial scan.'}

            detailed_cmd = ['nmap', '-p', ','.join(open_ports), '-oX', '-']
            detailed_cmd += self._profile_args()
            if self.nmap_args:
                detailed_cmd += shlex.split(self.nmap_args)
            detailed_cmd.append(self.target)

            detailed_result = self._run_command(detailed_cmd, timeout, stage='detailed')
            return self.parse_results(detailed_result.stdout)
        except FileNotFoundError:
            return {'error': "'nmap' command not found. Make sure it's installed and in your PATH."}
        except subprocess.TimeoutExpired:
            return {'error': f"Nmap scan timed out after {timeout} seconds."}
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or '').strip()
            return {'error': f"Error running Nmap: {stderr or 'unknown error'}"}

    def parse_results(self, xml_output: Optional[str]) -> List[Dict]:
        if not xml_output:
            return []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return []

        hosts: List[Dict] = []
        for host in root.findall('host'):
            address = host.find('address')
            ip = address.get('addr') if address is not None else 'unknown'
            host_info = {'ip': ip, 'ports': []}

            ports = host.find('ports')
            if ports is None:
                hosts.append(host_info)
                continue

            for port in ports.findall('port'):
                state_node = port.find('state')
                service_node = port.find('service')

                port_info = {
                    'portid': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'state': state_node.get('state') if state_node is not None else 'unknown',
                    'service': {},
                    'scripts': []
                }

                if service_node is not None:
                    port_info['service'] = {
                        'name': service_node.get('name'),
                        'product': service_node.get('product'),
                        'version': service_node.get('version')
                    }

                for script in port.findall('script'):
                    port_info['scripts'].append({
                        'id': script.get('id'),
                        'output': script.get('output')
                    })

                host_info['ports'].append(port_info)

            hosts.append(host_info)

        return hosts

    def _parse_open_ports(self, xml_output: Optional[str]) -> List[str]:
        if not xml_output:
            return []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return []

        open_ports: List[str] = []
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get('state') == 'open':
                open_ports.append(port.get('portid'))
        return open_ports

    def _run_command(self, command: List[str], timeout: Optional[int], stage: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        self._write_log(command, result.stdout, result.stderr, stage=stage)
        return result

    def _profile_args(self) -> List[str]:
        profiles = {
            'fast': ['-T4', '-sV', '--version-light'],
            'default': ['-T4', '-sV', '-sC'],
            'deep': ['-T4', '-sV', '-sC', '-A']
        }
        return profiles.get(self.profile, profiles['default']).copy()

    def _write_log(self, command: List[str], stdout: str, stderr: str, stage: str) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        mode = 'w' if stage == 'quick' else 'a'
        with open(self.log_file, mode) as log:
            log.write(f"# Stage: {stage}\n")
            log.write(f"$ {' '.join(command)}\n")
            if stdout:
                log.write("\n--- STDOUT ---\n")
                log.write(stdout)
            if stderr:
                log.write("\n--- STDERR ---\n")
                log.write(stderr)
            log.write("\n")
