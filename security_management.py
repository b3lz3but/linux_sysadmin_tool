
import subprocess
from core import logger

def update_system_security():
    try:
        subprocess.run(['sudo', 'apt', 'update'], check=True)
        subprocess.run(['sudo', 'apt', 'dist-upgrade', '-y'], check=True)
        logger.info("System security updates completed successfully.")
        print("Security updates completed.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update system security: {e}")
        print(f"An error occurred: {e}")
