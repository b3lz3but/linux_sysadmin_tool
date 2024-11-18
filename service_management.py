
import subprocess
from core import logger, validate_service_name

def manage_service(action, service_name):
    service_name = validate_service_name(service_name)
    try:
        subprocess.run(['sudo', 'systemctl', action, service_name], check=True)
        logger.info(f"Service '{service_name}' {action}ed successfully.")
        print(f"Service '{service_name}' has been {action}ed.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to {action} service '{service_name}': {e}")
        print(f"An error occurred: {e}")
