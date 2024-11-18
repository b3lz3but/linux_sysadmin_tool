
# Core utilities: logging, configuration, and validation.

import os
import logging
import yaml

# Logging setup
LOG_FILE = "sysadmin_tool.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("Core")

# Load configuration
CONFIG_FILE = "config.yaml"

def load_config():
    try:
        with open(CONFIG_FILE, "r") as file:
            config = yaml.safe_load(file)
        logger.info("Configuration loaded successfully.")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {CONFIG_FILE} not found.")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        return {}

# Input validation utilities
def validate_username(username):
    if not username.isalnum():
        raise ValueError("Invalid username: Must be alphanumeric.")
    return username

def validate_service_name(service_name):
    if " " in service_name:
        raise ValueError("Invalid service name: No spaces allowed.")
    return service_name
