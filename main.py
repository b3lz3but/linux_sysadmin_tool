
import importlib
import os
from core import logger, display_readme, load_config

# Dynamically load all modules in the same directory
def load_modules():
    modules = {}
    for file in os.listdir(os.path.dirname(__file__)):
        if file.endswith(".py") and file not in ["main.py", "core.py"]:
            module_name = file[:-3]
            try:
                modules[module_name] = importlib.import_module(module_name)
                logger.info(f"Module {module_name} loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load module {module_name}: {e}")
    return modules

def main_menu(modules):
    while True:
        print("\n=== Linux SysAdmin Tool ===")
        print("1. User Management")
        print("2. Service Management")
        print("3. Network Management")
        print("4. System Monitoring")
        print("5. Filesystem Management")
        print("6. Security Management")
        print("7. Display README")
        print("0. Exit")
        choice = input("Select an option: ")

        try:
            if choice == '1':
                username = input("Enter username for user management: ")
                modules['user_management'].add_user(username)
            elif choice == '2':
                service = input("Enter service name: ")
                modules['service_management'].manage_service('start', service)
            elif choice == '3':
                host = input("Enter host to ping: ")
                modules['network_management'].ping_host(host)
            elif choice == '4':
                modules['system_monitoring'].display_resource_usage()
            elif choice == '5':
                device = input("Enter device path: ")
                modules['filesystem_management'].format_and_mount_disk(device)
            elif choice == '6':
                modules['security_management'].update_system_security()
            elif choice == '7':
                display_readme()
            elif choice == '0':
                logger.info("Exiting the Linux SysAdmin Tool.")
                break
            else:
                print("Invalid option. Please try again.")
        except KeyError as e:
            print(f"Selected module is not available: {e}")
        except Exception as e:
            logger.error(f"An error occurred during menu operation: {e}")
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    config = load_config()
    modules = load_modules()
    main_menu(modules)
