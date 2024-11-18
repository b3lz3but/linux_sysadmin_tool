
import subprocess
from core import logger

def ping_host(host):
    try:
        subprocess.run(['ping', '-c', '4', host], check=True)
        logger.info(f"Ping to host {host} successful.")
        print(f"Ping to {host} completed.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Ping to host {host} failed: {e}")
        print(f"An error occurred: {e}")

def display_interfaces():
    try:
        subprocess.run(['ip', 'addr'], check=True)
        logger.info("Displayed network interfaces.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to display network interfaces: {e}")
        print(f"An error occurred: {e}")
