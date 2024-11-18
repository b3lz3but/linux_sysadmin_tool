
# Configuration manager for handling system defaults
import yaml

CONFIG_FILE = "config.yaml"

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as file:
            config = yaml.safe_load(file)
        return config
    except FileNotFoundError:
        return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as file:
        yaml.safe_dump(config, file)
    