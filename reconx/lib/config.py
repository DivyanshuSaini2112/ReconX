import configparser
import os

def get_api_key(service):
    """Reads an API key from the config.ini file."""
    config = configparser.ConfigParser()
    # Look for config.ini in the same directory as this script
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.ini')
    if os.path.exists(config_path):
        config.read(config_path)
        return config.get('API_KEYS', service, fallback=None)
    return None
