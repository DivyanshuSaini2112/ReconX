import requests
import time
import os
import json
from reconx.lib.config import get_api_key

class UrlScanScanner:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.api_key = get_api_key('URLSCAN_API_KEY')
        self.log_file = os.path.join(self.output_dir, 'urlscan.log')

    def _log(self, message):
        """Helper to write logs."""
        with open(self.log_file, 'a') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

    def run_scan(self, timeout=300):
        if not self.api_key:
            return {'error': 'URLScan.io API key not found.'}

        headers = {'API-Key': self.api_key, 'Content-Type': 'application/json'}
        data = {"url": self.target, "visibility": "public"}

        try:
            self._log("Submitting scan to URLScan.io...")
            response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))

            # Save the submission response for debugging
            with open(os.path.join(self.output_dir, 'urlscan_submission.json'), 'w') as f:
                json.dump(response.json(), f)

            if response.status_code != 200:
                error_msg = f"URLScan.io API request failed with status code {response.status_code}: {response.text}"
                self._log(f"ERROR: {error_msg}")
                return {'error': error_msg}

            submit_data = response.json()
            if 'api' not in submit_data:
                error_msg = f"Unexpected response from URLScan.io: {submit_data}"
                self._log(f"ERROR: {error_msg}")
                return {'error': error_msg}

            result_url = submit_data['api']
            self._log(f"Scan submitted successfully. Polling for results at: {result_url}")

            start_time = time.time()
            while time.time() - start_time < timeout:
                time.sleep(10)
                self._log("Polling for results...")
                result_response = requests.get(result_url)

                if result_response.status_code == 200:
                    self._log("Results received successfully.")
                    result_data = result_response.json()
                    output_file = os.path.join(self.output_dir, 'urlscan_results.json')
                    with open(output_file, 'w') as f:
                        json.dump(result_data, f, indent=4)

                    # Generate the detailed HTML report
                    self._generate_html_report(result_data)

                    return self.parse_results(result_data)

                elif result_response.status_code == 404:
                    self._log("Scan not finished yet, continuing to poll.")
                    continue
                else:
                    error_msg = f"Failed to fetch results. Status: {result_response.status_code}, Response: {result_response.text}"
                    self._log(f"ERROR: {error_msg}")
                    return {'error': error_msg}

            timeout_msg = 'URLScan.io scan timed out.'
            self._log(f"ERROR: {timeout_msg}")
            return {'error': timeout_msg}

        except requests.exceptions.RequestException as e:
            error_msg = f"An error occurred while communicating with the URLScan.io API: {e}"
            self._log(f"ERROR: {error_msg}")
            return {'error': error_msg}

    def parse_results(self, data):
        """Parses the JSON response from urlscan.io."""
        parsed = {
            'technologies': [],
            'ips': [],
            'domains': [],
            'network_calls': []
        }

        if 'data' in data and 'requests' in data['data']:
             for req in data['data']['requests']:
                if 'request' in req and 'url' in req['request']:
                    parsed['network_calls'].append(req['request']['url'])

        if 'lists' in data and 'domains' in data['lists']:
            parsed['domains'] = data['lists']['domains']

        if 'lists' in data and 'ips' in data['lists']:
            parsed['ips'] = data['lists']['ips']

        if 'verdicts' in data and 'overall' in data['verdicts'] and 'brands' in data['verdicts']['overall']:
            for brand in data['verdicts']['overall']['brands']:
                 parsed['technologies'].append(brand['name'])

        return parsed

    def get_command(self):
        """Returns the command that would be executed."""
        return ["requests.post('https://urlscan.io/api/v1/scan/', ...)"]

    def _generate_html_report(self, data):
        """Generates a detailed HTML report from the urlscan.io data."""
        report_path = os.path.join(self.output_dir, 'urlscan_report.html')

        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>URLScan.io Report</title>
            <style>
                body { font-family: sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }
                h1, h2 { color: #333; border-bottom: 2px solid #ddd; padding-bottom: 5px; }
                .container { background: #fff; padding: 2em; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1em; }
                .card { background: #f9f9f9; padding: 1em; border-radius: 5px; }
                .code { background: #eee; padding: 0.5em; border-radius: 3px; font-family: monospace; white-space: pre-wrap; word-wrap: break-word; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>URLScan.io Detailed Report</h1>
        """

        # Summary Section
        if 'task' in data:
            html += f"<h2>Summary for {data['task'].get('url', '')}</h2>"
            html += "<div class='grid'>"
            html += f"<div class='card'><b>Verdict:</b> {data.get('verdicts', {}).get('overall', {}).get('score', 'N/A')}</div>"
            html += f"<div class='card'><b>Malicious:</b> {data.get('verdicts', {}).get('overall', {}).get('malicious', 'N/A')}</div>"
            html += f"<div class='card'><b>IPs:</b> {len(data.get('lists', {}).get('ips', []))}</div>"
            html += f"<div class='card'><b>Domains:</b> {len(data.get('lists', {}).get('domains', []))}</div>"
            html += "</div>"

        # Technologies
        if data.get('verdicts', {}).get('overall', {}).get('brands'):
            html += "<h2>Detected Technologies</h2><table><tr><th>Name</th><th>Categories</th></tr>"
            for brand in data['verdicts']['overall']['brands']:
                html += f"<tr><td>{brand.get('name', '')}</td><td>{', '.join(brand.get('categories', []))}</td></tr>"
            html += "</table>"

        # Network Requests
        if data.get('data', {}).get('requests'):
            html += "<h2>Network Requests</h2><table><tr><th>URL</th><th>Status</th><th>Content-Type</th></tr>"
            for req in data['data']['requests']:
                html += f"<tr><td class='code'>{req.get('request', {}).get('url', '')}</td><td>{req.get('response', {}).get('status', 'N/A')}</td><td>{req.get('response', {}).get('headers', {}).get('content-type', ['N/A'])[0]}</td></tr>"
            html += "</table>"

        html += """
            </div>
        </body>
        </html>
        """

        try:
            with open(report_path, 'w') as f:
                f.write(html)
            self._log(f"Successfully generated URLScan.io HTML report at {report_path}")
        except IOError as e:
            self._log(f"Error saving URLScan.io HTML report: {e}")
