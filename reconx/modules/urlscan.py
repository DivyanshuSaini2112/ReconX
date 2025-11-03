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

    def run_scan(self, timeout=300):
        if not self.api_key:
            return {'error': 'URLScan.io API key not found.'}

        headers = {'API-Key': self.api_key, 'Content-Type': 'application/json'}
        data = {"url": self.target, "visibility": "public"}

        try:
            response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
            if response.status_code != 200:
                return {'error': f"URLScan.io API request failed with status code {response.status_code}: {response.text}"}

            submit_data = response.json()
            if 'api' not in submit_data:
                return {'error': f"Unexpected response from URLScan.io: {submit_data}"}

            result_url = submit_data['api']

            # Poll for results
            start_time = time.time()
            while time.time() - start_time < timeout:
                time.sleep(10)
                result_response = requests.get(result_url)
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    # Save the full report
                    output_file = os.path.join(self.output_dir, 'urlscan_results.json')
                    with open(output_file, 'w') as f:
                        json.dump(result_data, f, indent=4)

                    return self.parse_results(result_data)

            return {'error': 'URLScan.io scan timed out.'}

        except requests.exceptions.RequestException as e:
            return {'error': f"An error occurred while communicating with the URLScan.io API: {e}"}

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
