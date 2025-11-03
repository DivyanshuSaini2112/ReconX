import configparser
import os

def get_api_key(service):
    """Reads an API key from a config.ini file."""
    config = configparser.ConfigParser()

    # List of paths to check for the config file
    potential_paths = [
        os.path.join(os.getcwd(), 'config.ini'),
        os.path.join(os.getcwd(), 'reconx', 'config.ini')
    ]

    config_path = None
    for path in potential_paths:
        if os.path.exists(path):
            config_path = path
            break

    if config_path:
        config.read(config_path)
        return config.get('API_KEYS', service, fallback=None)

    return None
