
import subprocess
from core import logger, validate_username

def add_user(username):
    username = validate_username(username)
    try:
        subprocess.run(['sudo', 'adduser', username], check=True)
        logger.info(f"User '{username}' added successfully.")
        print(f"User '{username}' has been added.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to add user '{username}': {e}")
        print(f"An error occurred: {e}")

def delete_user(username):
    username = validate_username(username)
    confirm = input(f"Are you sure you want to delete user '{username}'? (y/n): ").lower()
    if confirm == 'y':
        try:
            subprocess.run(['sudo', 'deluser', '--remove-home', username], check=True)
            logger.info(f"User '{username}' deleted successfully.")
            print(f"User '{username}' has been deleted.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete user '{username}': {e}")
            print(f"An error occurred: {e}")
    else:
        print("Operation canceled.")
