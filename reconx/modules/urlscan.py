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

            if response.status_code != 200:
                error_msg = f"URLScan.io API request failed with status code {response.status_code}: {response.text}"
                self._log(f"ERROR: {error_msg}")
                return {'error': error_msg}

            submit_data = response.json()
            self._log(f"Submission response: {json.dumps(submit_data)}")
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
                    self._log(f"Result payload: {json.dumps(result_data)}")

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
