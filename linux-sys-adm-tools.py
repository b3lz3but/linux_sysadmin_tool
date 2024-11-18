#!/usr/bin/env python3

import subprocess
import sys
import os
import shutil
import datetime
import tempfile
import psutil
import time
import socket
import platform
import json
import logging
import glob
import pwd
import grp
from crontab import CronTab

# README content
README_CONTENT = """# Linux SysAdmin Tool

## Overview
The Linux SysAdmin Tool is a comprehensive command-line interface (CLI) application designed to simplify common system administration tasks on Linux systems. It provides an interactive menu-driven interface for managing users, services, networks, system monitoring, and more.

## Features
- **User Management**
  - Add/Delete users
  - Reset passwords
  - Modify group memberships
  - Lock/Unlock user accounts

- **Service Management**
  - Start/Stop/Restart services
  - Enable/Disable services
  - Check service status
  - List running services

- **Network Management**
  - Test connectivity
  - Configure network interfaces
  - Display active connections
  - Test port connectivity

- **System Monitoring**
  - Display resource usage
  - Monitor processes
  - Check disk usage
  - Real-time process monitoring

- **Process Management**
  - List processes
  - Kill processes
  - Set process priorities

- **Scheduled Tasks**
  - Create and manage cron jobs
  - View scheduled tasks
  - Enable/disable scheduled tasks

- **Package Management**
  - Update system packages
  - Install/Remove packages
  - Search packages
  - Clean package cache

- **Firewall Management**
  - Configure firewall rules
  - Enable/disable firewall
  - Monitor connections

- **Log Management**
  - View system logs
  - Monitor log files
  - Analyze logs
  - Manage log rotation

- **Backup Management**
  - Create system backups
  - Restore from backups
  - Schedule automated backups
  - Verify backup integrity

- **Filesystem Management**
  - Mount/unmount filesystems
  - Check filesystem health
  - Manage disk partitions
  - Monitor disk space

- **Security Management**
  - Configure system security
  - Manage SSL certificates
  - Configure SSH
  - Manage user permissions

- **System Information**
  - View hardware information
  - Check system status
  - Monitor performance
  - Generate system reports

- **Performance Monitoring**
  - Real-time system monitoring
  - Performance analysis
  - Resource usage tracking
  - Generate performance reports

## Requirements
- Python 3.x
- Required Python modules:
  - psutil
  - python-crontab
- Root/sudo privileges for system operations

## Installation
1. Install required packages:
   ```bash
   sudo apt-get install python3-psutil python3-crontab
   ```

2. Set up required directories:
   ```bash
   sudo mkdir -p /etc/sysadmin_tool /var/log/sysadmin_tool /var/backups/sysadmin_tool
   ```

3. Set appropriate permissions:
   ```bash
   sudo chmod 755 /etc/sysadmin_tool
   sudo chmod 755 /var/log/sysadmin_tool
   sudo chmod 755 /var/backups/sysadmin_tool
   ```

## Usage
Run the script with sudo privileges:
```bash
sudo python3 sysadmin_tool.py
```

## Security Note
This tool requires root privileges for many operations. Use with caution and ensure proper security measures are in place.
"""


def display_readme():
    """Display the README content using less pager"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(README_CONTENT)
        temp_filename = f.name

    try:
        subprocess.run(["less", temp_filename])
    finally:
        os.unlink(temp_filename)


# --- Utility Functions ---
def check_root():
    """Check if the script is running with root privileges"""
    return os.geteuid() == 0


def backup_file(file_path):
    """Create a backup of a file"""
    backup_path = f"{file_path}.bak.{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        shutil.copy2(file_path, backup_path)
        return True
    except Exception as e:
        print(f"Error creating backup: {e}")
        return False


def restore_file(file_path):
    """Restore a file from its most recent backup"""
    try:
        backups = sorted(glob.glob(f"{file_path}.bak.*"))
        if backups:
            latest_backup = backups[-1]
            shutil.copy2(latest_backup, file_path)
            return True
        else:
            print("No backup files found")
            return False
    except Exception as e:
        print(f"Error restoring backup: {e}")
        return False


def is_service_active(service_name):
    """Check if a service is active"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_system_info():
    """Get detailed system information"""
    info = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "kernel": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_cores": psutil.cpu_count(),
        "memory_total": psutil.virtual_memory().total,
        "disk_partitions": psutil.disk_partitions(),
        "network_interfaces": psutil.net_if_addrs(),
    }
    return info


def log_activity(activity):
    """Log admin activities"""
    log_file = "/var/log/sysadmin_tool/sysadmin.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = os.getenv("USER")
    log_entry = f"{timestamp} - User: {user} - {activity}\n"

    try:
        with open(log_file, "a") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing to log: {e}")


def validate_ip(ip):
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def get_file_permissions(path):
    """Get file permissions in human-readable format"""
    try:
        mode = os.stat(path).st_mode
        return {
            "owner": pwd.getpwuid(os.stat(path).st_uid).pw_name,
            "group": grp.getgrgid(os.stat(path).st_gid).gr_name,
            "permissions": oct(mode)[-3:],
        }
    except Exception as e:
        return f"Error getting permissions: {e}"


def check_disk_space(threshold=90):
    """Check disk space usage and alert if above threshold"""
    disk_usage = psutil.disk_usage("/")
    usage_percent = disk_usage.percent

    if usage_percent >= threshold:
        print(f"WARNING: Disk usage is at {usage_percent}%")
        return False
    return True


# --- User Management Functions ---
def user_management():
    while True:
        print("\n--- User Management ---")
        print("1. Add a User")
        print("2. Delete a User")
        print("3. Reset User Password")
        print("4. Modify Group Membership")
        print("5. Lock/Unlock User Account")
        print("6. List All Users")
        print("7. Check User Information")
        print("0. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == "1":
            add_user()
        elif choice == "2":
            delete_user()
        elif choice == "3":
            reset_password()
        elif choice == "4":
            modify_group()
        elif choice == "5":
            lock_unlock_user()
        elif choice == "6":
            list_users()
        elif choice == "7":
            check_user_info()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def add_user():
    username = input("Enter the new username: ")
    create_home = input("Create home directory? (y/n): ").lower() == "y"
    add_to_sudo = input("Add to sudo group? (y/n): ").lower() == "y"

    try:
        cmd = ["sudo", "useradd"]
        if create_home:
            cmd.extend(["-m"])
        cmd.append(username)

        subprocess.run(cmd, check=True)

        # Set password
        subprocess.run(["sudo", "passwd", username], check=True)

        if add_to_sudo:
            subprocess.run(["sudo", "usermod", "-aG", "sudo", username], check=True)

        print(f"User '{username}' has been added successfully.")
        log_activity(f"Added new user: {username}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        log_activity(f"Failed to add user: {username}")


def delete_user():
    username = input("Enter the username to delete: ")
    remove_home = input("Remove home directory? (y/n): ").lower() == "y"
    backup_home = input("Backup home directory before deletion? (y/n): ").lower() == "y"

    try:
        if backup_home and os.path.exists(f"/home/{username}"):
            backup_path = f"/var/backups/home_{username}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            subprocess.run(
                ["sudo", "cp", "-r", f"/home/{username}", backup_path], check=True
            )
            print(f"Home directory backed up to {backup_path}")

        cmd = ["sudo", "userdel"]
        if remove_home:
            cmd.append("-r")
        cmd.append(username)

        subprocess.run(cmd, check=True)
        print(f"User '{username}' has been deleted.")
        log_activity(f"Deleted user: {username}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        log_activity(f"Failed to delete user: {username}")


def reset_password():
    username = input("Enter the username to reset the password for: ")
    try:
        subprocess.run(["sudo", "passwd", username], check=True)
        print(f"Password for user '{username}' has been reset.")
        log_activity(f"Reset password for user: {username}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        log_activity(f"Failed to reset password for user: {username}")


def modify_group():
    while True:
        print("\n--- Group Modification ---")
        print("1. Add User to Group")
        print("2. Remove User from Group")
        print("3. Create New Group")
        print("4. Delete Group")
        print("5. List User's Groups")
        print("0. Back")

        choice = input("Select an option: ")

        if choice == "1":
            username = input("Enter username: ")
            group = input("Enter group name: ")
            try:
                subprocess.run(["sudo", "usermod", "-aG", group, username], check=True)
                print(f"Added user '{username}' to group '{group}'")
                log_activity(f"Added user {username} to group {group}")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "2":
            username = input("Enter username: ")
            group = input("Enter group name: ")
            try:
                subprocess.run(["sudo", "gpasswd", "-d", username, group], check=True)
                print(f"Removed user '{username}' from group '{group}'")
                log_activity(f"Removed user {username} from group {group}")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "3":
            group = input("Enter new group name: ")
            try:
                subprocess.run(["sudo", "groupadd", group], check=True)
                print(f"Created group '{group}'")
                log_activity(f"Created new group: {group}")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "4":
            group = input("Enter group name to delete: ")
            try:
                subprocess.run(["sudo", "groupdel", group], check=True)
                print(f"Deleted group '{group}'")
                log_activity(f"Deleted group: {group}")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "5":
            username = input("Enter username: ")
            try:
                subprocess.run(["groups", username])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "0":
            break


def lock_unlock_user():
    username = input("Enter username: ")
    action = input("Lock or unlock account? (l/u): ").lower()

    try:
        if action == "l":
            subprocess.run(["sudo", "passwd", "-l", username], check=True)
            print(f"Account '{username}' has been locked.")
            log_activity(f"Locked user account: {username}")
        elif action == "u":
            subprocess.run(["sudo", "passwd", "-u", username], check=True)
            print(f"Account '{username}' has been unlocked.")
            log_activity(f"Unlocked user account: {username}")
        else:
            print("Invalid action selected.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def list_users():
    try:
        print("\nSystem Users:")
        with open("/etc/passwd", "r") as f:
            for line in f:
                user_info = line.split(":")
                if int(user_info[2]) >= 1000 and user_info[0] != "nobody":
                    print(f"Username: {user_info[0]}")
                    print(f"User ID: {user_info[2]}")
                    print(f"Home Directory: {user_info[5]}")
                    print(f"Shell: {user_info[6].strip()}")
                    print("-" * 30)
    except Exception as e:
        print(f"An error occurred: {e}")


def check_user_info():
    username = input("Enter username to check: ")
    try:
        # Basic user information
        subprocess.run(["id", username])

        # Login information
        print("\nLast login information:")
        subprocess.run(["last", username, "-n", "5"])

        # Password status
        print("\nPassword status:")
        subprocess.run(["sudo", "chage", "-l", username])

        # Check if user is locked
        passwd_status = subprocess.run(
            ["sudo", "passwd", "-S", username], capture_output=True, text=True
        )
        if "L" in passwd_status.stdout:
            print("\nAccount status: Locked")
        else:
            print("\nAccount status: Active")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


# --- Service Management Functions ---
def service_management():
    while True:
        print("\n--- Service Management ---")
        print("1. Start a Service")
        print("2. Stop a Service")
        print("3. Restart a Service")
        print("4. Enable a Service")
        print("5. Disable a Service")
        print("6. Check Service Status")
        print("7. List Running Services")
        print("8. Show Service Logs")
        print("0. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == "1":
            manage_service("start")
        elif choice == "2":
            manage_service("stop")
        elif choice == "3":
            manage_service("restart")
        elif choice == "4":
            enable_disable_service("enable")
        elif choice == "5":
            enable_disable_service("disable")
        elif choice == "6":
            check_service_status()
        elif choice == "7":
            list_running_services()
        elif choice == "8":
            show_service_logs()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def manage_service(action):
    service_name = input("Enter the service name: ")
    try:
        subprocess.run(["sudo", "systemctl", action, service_name], check=True)
        print(f"Service '{service_name}' has been {action}ed.")
        log_activity(f"{action.capitalize()}ed service: {service_name}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        log_activity(f"Failed to {action} service: {service_name}")


def enable_disable_service(action):
    service_name = input("Enter the service name: ")
    try:
        subprocess.run(["sudo", "systemctl", action, service_name], check=True)
        print(f"Service '{service_name}' has been {action}d.")
        log_activity(f"{action.capitalize()}d service: {service_name}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def check_service_status():
    service_name = input("Enter the service name: ")
    try:
        subprocess.run(["systemctl", "status", service_name])
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def list_running_services():
    try:
        print("\nRunning Services:")
        subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"])
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def show_service_logs():
    service_name = input("Enter the service name: ")
    lines = input("Enter number of lines to show (default: 50): ") or "50"
    try:
        subprocess.run(["journalctl", "-u", service_name, "-n", lines, "--no-pager"])
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


# --- Network Management Functions ---
def network_management():
    while True:
        print("\n--- Network Management ---")
        print("1. Show Network Interfaces")
        print("2. Configure Network Interface")
        print("3. Test Connectivity")
        print("4. Show Network Connections")
        print("5. DNS Lookup")
        print("6. Show Routing Table")
        print("7. Configure Firewall")
        print("8. Network Statistics")
        print("9. Bandwidth Monitor")
        print("10. Wi-Fi Management")
        print("0. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == "1":
            show_interfaces()
        elif choice == "2":
            configure_interface()
        elif choice == "3":
            test_connectivity()
        elif choice == "4":
            show_connections()
        elif choice == "5":
            dns_lookup()
        elif choice == "6":
            show_routing()
        elif choice == "7":
            configure_firewall()
        elif choice == "8":
            network_statistics()
        elif choice == "9":
            bandwidth_monitor()
        elif choice == "10":
            wifi_management()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def show_interfaces():
    try:
        print("\nNetwork Interface Information:")
        print("\n1. IP Configuration:")
        subprocess.run(["ip", "addr", "show"])

        print("\n2. Interface Statistics:")
        subprocess.run(["ip", "-s", "link"])

        print("\n3. Network Interfaces Status:")
        for interface, addresses in psutil.net_if_addrs().items():
            print(f"\nInterface: {interface}")
            for addr in addresses:
                print(f"  {addr.family.name}: {addr.address}")

            # Get interface statistics
            stats = psutil.net_if_stats().get(interface)
            if stats:
                print(f"  Speed: {stats.speed} Mb/s")
                print(f"  MTU: {stats.mtu}")
                print(f"  Status: {'Up' if stats.isup else 'Down'}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def configure_interface():
    try:
        print("\nAvailable Network Interfaces:")
        subprocess.run(["ip", "link", "show"])

        interface = input("\nEnter interface name (e.g., eth0): ")
        action = input("Select action (up/down/set): ").lower()

        if action == "up":
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
            print(f"Interface {interface} is up")
        elif action == "down":
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            print(f"Interface {interface} is down")
        elif action == "set":
            ip_addr = input("Enter IP address with subnet (e.g., 192.168.1.10/24): ")
            subprocess.run(
                ["sudo", "ip", "addr", "add", ip_addr, "dev", interface], check=True
            )
            print(f"IP address {ip_addr} configured on {interface}")
        else:
            print("Invalid action")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def test_connectivity():
    while True:
        print("\n--- Connectivity Testing ---")
        print("1. Ping Test")
        print("2. Traceroute")
        print("3. Port Test")
        print("4. MTR (My Traceroute)")
        print("0. Back")

        choice = input("Select an option: ")

        if choice == "1":
            host = input("Enter hostname or IP to ping: ")
            count = input("Enter number of pings (default: 4): ") or "4"
            try:
                subprocess.run(["ping", "-c", count, host])
            except subprocess.CalledProcessError as e:
                print(f"Could not reach {host}: {e}")

        elif choice == "2":
            host = input("Enter hostname or IP for traceroute: ")
            try:
                subprocess.run(["traceroute", host])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "3":
            host = input("Enter hostname or IP: ")
            port = input("Enter port number: ")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    result = s.connect_ex((host, int(port)))
                    if result == 0:
                        print(f"Port {port} is open")
                    else:
                        print(f"Port {port} is closed")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == "4":
            host = input("Enter hostname or IP for MTR: ")
            try:
                subprocess.run(["sudo", "mtr", host])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "0":
            break


def show_connections():
    try:
        print("\nActive Network Connections:")
        subprocess.run(["ss", "-tunapl"])
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def dns_lookup():
    while True:
        print("\n--- DNS Lookup ---")
        print("1. Forward Lookup (Hostname to IP)")
        print("2. Reverse Lookup (IP to Hostname)")
        print("3. DNS Record Query")
        print("4. Check DNS Servers")
        print("0. Back")

        choice = input("Select an option: ")

        if choice == "1":
            hostname = input("Enter hostname: ")
            try:
                subprocess.run(["nslookup", hostname])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "2":
            ip = input("Enter IP address: ")
            try:
                subprocess.run(["nslookup", ip])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "3":
            domain = input("Enter domain name: ")
            record_type = input("Enter record type (A/MX/NS/TXT/CNAME): ").upper()
            try:
                subprocess.run(["dig", domain, record_type])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "4":
            try:
                print("\nDNS Servers:")
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            print(line.strip())
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == "0":
            break


def show_routing():
    try:
        print("\nRouting Table:")
        subprocess.run(["ip", "route", "show"])

        print("\nRouting Statistics:")
        subprocess.run(["netstat", "-r"])
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def network_statistics():
    try:
        print("\nNetwork Statistics:")
        print("\n1. Protocol Statistics:")
        subprocess.run(["netstat", "-s"])

        print("\n2. Interface Statistics:")
        subprocess.run(["netstat", "-i"])

        print("\n3. Network Device Statistics:")
        with open("/proc/net/dev", "r") as f:
            print(f.read())
    except Exception as e:
        print(f"An error occurred: {e}")


def bandwidth_monitor():
    try:
        print("Monitoring bandwidth usage (Press Ctrl+C to stop)")
        old_stats = psutil.net_io_counters()
        while True:
            time.sleep(1)
            new_stats = psutil.net_io_counters()

            bytes_sent = new_stats.bytes_sent - old_stats.bytes_sent
            bytes_recv = new_stats.bytes_recv - old_stats.bytes_recv

            print(
                f"\rUpload: {bytes_sent/1024:.2f} KB/s | Download: {bytes_recv/1024:.2f} KB/s",
                end="",
            )

            old_stats = new_stats
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"\nAn error occurred: {e}")


def wifi_management():
    while True:
        print("\n--- Wi-Fi Management ---")
        print("1. Show Available Networks")
        print("2. Connect to Network")
        print("3. Disconnect from Network")
        print("4. Show Current Connection")
        print("5. Save Network Configuration")
        print("0. Back")

        choice = input("Select an option: ")

        if choice == "1":
            try:
                subprocess.run(["sudo", "iwlist", "scanning"])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "2":
            ssid = input("Enter network SSID: ")
            password = input("Enter network password: ")
            try:
                # Using wpa_supplicant for Wi-Fi connection
                config = f"""
                network={{
                    ssid="{ssid}"
                    psk="{password}"
                }}
                """
                with open("/tmp/wifi_config", "w") as f:
                    f.write(config)
                subprocess.run(
                    ["sudo", "wpa_supplicant", "-i", "wlan0", "-c", "/tmp/wifi_config"]
                )
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == "3":
            try:
                subprocess.run(["sudo", "ifconfig", "wlan0", "down"])
                print("Disconnected from Wi-Fi")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "4":
            try:
                subprocess.run(["iwconfig"])
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "5":
            try:
                subprocess.run(["sudo", "wpa_cli", "save_config"])
                print("Network configuration saved")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")

        elif choice == "0":
            break


# --- System Monitoring Functions ---
def system_monitoring():
    while True:
        print("\n--- System Monitoring ---")
        print("1. Show System Resources")
        print("2. Show Process List")
        print("3. Show Disk Usage")
        print("4. Show Memory Usage")
        print("5. Show CPU Information")
        print("6. Show System Load")
        print("7. Monitor Real-time Resources")
        print("8. Show Running Services")
        print("9. Temperature Sensors")
        print("10. System Uptime")
        print("0. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == "1":
            show_system_resources()
        elif choice == "2":
            show_process_list()
        elif choice == "3":
            show_disk_usage()
        elif choice == "4":
            show_memory_usage()
        elif choice == "5":
            show_cpu_info()
        elif choice == "6":
            show_system_load()
        elif choice == "7":
            monitor_realtime()
        elif choice == "8":
            show_running_services()
        elif choice == "9":
            show_temperature()
        elif choice == "10":
            show_uptime()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def show_system_resources():
    try:
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        print("\nCPU Usage per Core:")
        for i, percent in enumerate(cpu_percent):
            print(f"Core {i}: {percent}%")

        # Memory Usage
        memory = psutil.virtual_memory()
        print("\nMemory Usage:")
        print(f"Total: {memory.total / (1024**3):.2f} GB")
        print(f"Available: {memory.available / (1024**3):.2f} GB")
        print(f"Used: {memory.used / (1024**3):.2f} GB ({memory.percent}%)")

        # Disk Usage
        disk = psutil.disk_usage("/")
        print("\nDisk Usage:")
        print(f"Total: {disk.total / (1024**3):.2f} GB")
        print(f"Used: {disk.used / (1024**3):.2f} GB ({disk.percent}%)")
        print(f"Free: {disk.free / (1024**3):.2f} GB")

        # Network IO
        net_io = psutil.net_io_counters()
        print("\nNetwork I/O:")
        print(f"Bytes Sent: {net_io.bytes_sent / (1024**2):.2f} MB")
        print(f"Bytes Received: {net_io.bytes_recv / (1024**2):.2f} MB")

    except Exception as e:
        print(f"An error occurred: {e}")


def show_process_list():
    try:
        print("\nProcess List:")
        processes = []
        for proc in psutil.process_iter(
            ["pid", "name", "username", "cpu_percent", "memory_percent"]
        ):
            try:
                pinfo = proc.info
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Sort by CPU usage
        processes.sort(key=lambda x: x["cpu_percent"], reverse=True)

        print("\nTop Processes by CPU Usage:")
        print("PID\tCPU%\tMEM%\tUSER\tNAME")
        for proc in processes[:20]:  # Show top 20 processes
            print(
                f"{proc['pid']}\t{proc['cpu_percent']:.1f}\t{proc['memory_percent']:.1f}\t{proc['username']}\t{proc['name']}"
            )

    except Exception as e:
        print(f"An error occurred: {e}")


def show_disk_usage():
    try:
        print("\nDisk Partitions and Usage:")
        partitions = psutil.disk_partitions()
        for partition in partitions:
            print(f"\nDevice: {partition.device}")
            print(f"Mountpoint: {partition.mountpoint}")
            print(f"File System Type: {partition.fstype}")

            try:
                usage = psutil.disk_usage(partition.mountpoint)
                print(f"Total Size: {usage.total / (1024**3):.2f} GB")
                print(f"Used: {usage.used / (1024**3):.2f} GB ({usage.percent}%)")
                print(f"Free: {usage.free / (1024**3):.2f} GB")
            except PermissionError:
                print("Permission denied")

        # Show disk IO statistics
        print("\nDisk I/O Statistics:")
        disk_io = psutil.disk_io_counters()
        print(f"Read: {disk_io.read_bytes / (1024**3):.2f} GB")
        print(f"Written: {disk_io.write_bytes / (1024**3):.2f} GB")

    except Exception as e:
        print(f"An error occurred: {e}")


def show_memory_usage():
    try:
        # Virtual Memory
        virtual = psutil.virtual_memory()
        print("\nVirtual Memory:")
        print(f"Total: {virtual.total / (1024**3):.2f} GB")
        print(f"Available: {virtual.available / (1024**3):.2f} GB")
        print(f"Used: {virtual.used / (1024**3):.2f} GB ({virtual.percent}%)")
        print(f"Free: {virtual.free / (1024**3):.2f} GB")
        print(f"Buffered: {virtual.buffers / (1024**3):.2f} GB")
        print(f"Cached: {virtual.cached / (1024**3):.2f} GB")

        # Swap Memory
        swap = psutil.swap_memory()
        print("\nSwap Memory:")
        print(f"Total: {swap.total / (1024**3):.2f} GB")
        print(f"Used: {swap.used / (1024**3):.2f} GB ({swap.percent}%)")
        print(f"Free: {swap.free / (1024**3):.2f} GB")

        # Memory by Process
        print("\nTop Memory Consuming Processes:")
        processes = []
        for proc in psutil.process_iter(["pid", "name", "memory_percent"]):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        processes.sort(key=lambda x: x["memory_percent"], reverse=True)
        print("\nPID\tMEM%\tNAME")
        for proc in processes[:10]:  # Show top 10 processes
            print(f"{proc['pid']}\t{proc['memory_percent']:.1f}\t{proc['name']}")

    except Exception as e:
        print(f"An error occurred: {e}")


def show_cpu_info():
    try:
        print("\nCPU Information:")

        # CPU Model
        with open("/proc/cpuinfo") as f:
            cpu_info = f.readlines()
        for line in cpu_info:
            if "model name" in line:
                print(f"Model: {line.split(':')[1].strip()}")
                break

        # CPU Cores
        print(f"Physical cores: {psutil.cpu_count(logical=False)}")
        print(f"Total cores: {psutil.cpu_count(logical=True)}")

        # CPU Frequencies
        cpu_freq = psutil.cpu_freq()
        if cpu_freq:
            print(f"Max Frequency: {cpu_freq.max:.2f} MHz")
            print(f"Min Frequency: {cpu_freq.min:.2f} MHz")
            print(f"Current Frequency: {cpu_freq.current:.2f} MHz")

        # CPU Usage
        print("\nCPU Usage Per Core:")
        for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
            print(f"Core {i}: {percentage}%")

        # CPU Times
        cpu_times = psutil.cpu_times()
        print("\nCPU Times:")
        print(f"User: {cpu_times.user} seconds")
        print(f"System: {cpu_times.system} seconds")
        print(f"Idle: {cpu_times.idle} seconds")

    except Exception as e:
        print(f"An error occurred: {e}")


def show_system_load():
    try:
        # Load averages
        load1, load5, load15 = os.getloadavg()
        cpu_count = psutil.cpu_count()

        print("\nSystem Load Averages:")
        print(f"1 minute: {load1:.2f} (Per CPU: {load1/cpu_count:.2f})")
        print(f"5 minutes: {load5:.2f} (Per CPU: {load5/cpu_count:.2f})")
        print(f"15 minutes: {load15:.2f} (Per CPU: {load15/cpu_count:.2f})")

        # CPU usage history
        print("\nCPU Usage History:")
        for i in range(3):  # Show 3 samples
            cpu_percent = psutil.cpu_percent(interval=1)
            print(f"Sample {i+1}: {cpu_percent}%")

    except Exception as e:
        print(f"An error occurred: {e}")


def monitor_realtime():
    try:
        print("Real-time System Monitor (Press Ctrl+C to stop)")
        while True:
            os.system("clear")  # Clear screen

            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            print("CPU Usage per Core:")
            for i, percent in enumerate(cpu_percent):
                print(f"Core {i}: {percent}% {'#' * int(percent/2)}")

            # Memory Usage
            memory = psutil.virtual_memory()
            print(f"\nMemory Usage: {memory.percent}%")
            memory_bar = "#" * int(memory.percent / 2)
            print(
                f"[{memory_bar:<50}] {memory.used/(1024**3):.1f}GB/{memory.total/(1024**3):.1f}GB"
            )

            # Disk Usage
            disk = psutil.disk_usage("/")
            print(f"\nDisk Usage: {disk.percent}%")
            disk_bar = "#" * int(disk.percent / 2)
            print(
                f"[{disk_bar:<50}] {disk.used/(1024**3):.1f}GB/{disk.total/(1024**3):.1f}GB"
            )

            # Network Usage
            net_io = psutil.net_io_counters()
            print(f"\nNetwork I/O:")
            print(f"Upload: {net_io.bytes_sent/(1024**2):.2f} MB")
            print(f"Download: {net_io.bytes_recv/(1024**2):.2f} MB")

            # Most CPU-intensive processes
            print("\nTop CPU-Intensive Processes:")
            processes = []
            for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
                try:
                    pinfo = proc.info
                    if pinfo["cpu_percent"] > 0:
                        processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            processes.sort(key=lambda x: x["cpu_percent"], reverse=True)
            for proc in processes[:5]:
                print(
                    f"PID: {proc['pid']:<6} CPU: {proc['cpu_percent']:>5.1f}%  {proc['name']}"
                )

            time.sleep(2)

    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"An error occurred: {e}")


def show_temperature():
    try:
        print("\nSystem Temperature Sensors:")
        sensors_temperatures = psutil.sensors_temperatures()

        if not sensors_temperatures:
            print("No temperature sensors found")
            return

        for sensor_name, entries in sensors_temperatures.items():
            print(f"\n{sensor_name}:")
            for entry in entries:
                print(f"  {entry.label or 'Unknown'}: {entry.current}°C")
                if entry.high is not None:
                    print(f"  High threshold: {entry.high}°C")
                if entry.critical is not None:
                    print(f"  Critical threshold: {entry.critical}°C")

    except Exception as e:
        print(f"An error occurred: {e}")


def show_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])

        # Convert seconds to days, hours, minutes, seconds
        days = int(uptime_seconds // (24 * 3600))
        hours = int((uptime_seconds % (24 * 3600)) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)

        print(
            f"\nSystem Uptime: {days} days, {hours} hours, {minutes} minutes, {seconds} seconds"
        )

        # Show boot time
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        print(f"Boot Time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")

    except Exception as e:
        print(f"An error occurred: {e}")


# --- Process Management Functions ---
def process_management():
    while True:
        print("\n--- Process Management ---")
        print("1. List All Processes")
        print("2. Kill Process")
        print("3. Set Process Priority")
        print("4. Monitor Process Resources")
        print("5. Find Process by Name")
        print("6. Show Process Tree")
        print("7. Process Resource Usage")
        print("8. Thread Information")
        print("9. Process Memory Maps")
        print("0. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == "1":
            list_processes()
        elif choice == "2":
            kill_process()
        elif choice == "3":
            set_process_priority()
        elif choice == "4":
            monitor_process()
        elif choice == "5":
            find_process()
        elif choice == "6":
            show_process_tree()
        elif choice == "7":
            process_resource_usage()
        elif choice == "8":
            thread_information()
        elif choice == "9":
            process_memory_maps()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def list_processes():
    try:
        sort_by = input("Sort by (cpu/memory/pid/name): ").lower()
        processes = []
        for proc in psutil.process_iter(
            [
                "pid",
                "name",
                "username",
                "cpu_percent",
                "memory_percent",
                "create_time",
                "status",
            ]
        ):
            try:
                pinfo = proc.info
                pinfo["cpu_percent"] = proc.cpu_percent()
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if sort_by == "cpu":
            processes.sort(key=lambda x: x["cpu_percent"], reverse=True)
        elif sort_by == "memory":
            processes.sort(key=lambda x: x["memory_percent"], reverse=True)
        elif sort_by == "pid":
            processes.sort(key=lambda x: x["pid"])
        elif sort_by == "name":
            processes.sort(key=lambda x: x["name"].lower())

        print("\nPID\tCPU%\tMEM%\tSTATUS\tUSER\t\tNAME")
        print("-" * 70)
        for proc in processes[:50]:  # Show top 50 processes
            print(
                f"{proc['pid']}\t{proc['cpu_percent']:.1f}\t{proc['memory_percent']:.1f}\t{proc['status']}\t{proc['username'][:8]}\t{proc['name']}"
            )

    except Exception as e:
        print(f"An error occurred: {e}")


def kill_process():
    try:
        pid = input("Enter PID to kill: ")
        signal_type = input("Enter signal type (1=SIGTERM, 9=SIGKILL, 15=SIGTERM): ")

        confirm = input(
            f"Are you sure you want to kill process {pid} with signal {signal_type}? (y/n): "
        )
        if confirm.lower() == "y":
            subprocess.run(["sudo", "kill", f"-{signal_type}", pid], check=True)
            print(f"Signal {signal_type} sent to process {pid}")
            log_activity(f"Killed process {pid} with signal {signal_type}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def set_process_priority():
    try:
        pid = input("Enter PID: ")
        nice = input("Enter nice value (-20 to 19, lower = higher priority): ")

        subprocess.run(["sudo", "renice", nice, "-p", pid], check=True)
        print(f"Priority for process {pid} set to {nice}")
        log_activity(f"Changed priority of process {pid} to {nice}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def monitor_process():
    try:
        pid = int(input("Enter PID to monitor: "))
        interval = int(input("Enter update interval in seconds (default: 1): ") or "1")

        print("Monitoring process (Press Ctrl+C to stop)...")
        while True:
            try:
                process = psutil.Process(pid)
                print("\033[2J\033[H")  # Clear screen

                # Basic info
                print(f"Process: {process.name()} (PID: {pid})")
                print(f"Status: {process.status()}")
                print(
                    f"Started: {datetime.datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')}"
                )

                # CPU Usage
                print(f"\nCPU Usage: {process.cpu_percent()}%")

                # Memory Usage
                memory_info = process.memory_info()
                print(f"\nMemory Usage:")
                print(f"RSS: {memory_info.rss / (1024*1024):.2f} MB")
                print(f"VMS: {memory_info.vms / (1024*1024):.2f} MB")

                # IO Counters
                try:
                    io_counters = process.io_counters()
                    print(f"\nI/O:")
                    print(f"Read: {io_counters.read_bytes / (1024*1024):.2f} MB")
                    print(f"Written: {io_counters.write_bytes / (1024*1024):.2f} MB")
                except psutil.AccessDenied:
                    print("\nI/O: Access Denied")

                # Threads
                print(f"\nThreads: {process.num_threads()}")

                # Open Files
                try:
                    files = process.open_files()
                    print("\nOpen Files:")
                    for file in files[:5]:  # Show first 5 files
                        print(f"  {file.path}")
                except psutil.AccessDenied:
                    print("\nOpen Files: Access Denied")

                time.sleep(interval)

            except psutil.NoSuchProcess:
                print(f"\nProcess {pid} no longer exists")
                break

    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except ValueError as e:
        print(f"Invalid input: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


def find_process():
    try:
        name = input("Enter process name to find: ")
        processes = []

        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                if name.lower() in proc.info["name"].lower():
                    processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if processes:
            print("\nMatching processes:")
            print("PID\tUSER\t\tCOMMAND")
            print("-" * 70)
            for proc in processes:
                cmdline = (
                    " ".join(proc["cmdline"])
                    if proc["cmdline"]
                    else "[No Command Line]"
                )
                print(f"{proc['pid']}\t{proc['username'][:8]}\t{cmdline[:50]}")
        else:
            print(f"No processes found matching '{name}'")

    except Exception as e:
        print(f"An error occurred: {e}")


def show_process_tree():
    try:
        print("\nProcess Tree:")
        subprocess.run(["pstree", "-p"])
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def process_resource_usage():
    try:
        pid = int(input("Enter PID: "))
        process = psutil.Process(pid)

        print(f"\nDetailed Resource Usage for PID {pid} ({process.name()}):")

        # CPU Times
        cpu_times = process.cpu_times()
        print("\nCPU Times:")
        print(f"User: {cpu_times.user} seconds")
        print(f"System: {cpu_times.system} seconds")

        # Memory Details
        memory_info = process.memory_full_info()
        print("\nMemory Details:")
        print(f"RSS: {memory_info.rss / (1024*1024):.2f} MB")
        print(f"VMS: {memory_info.vms / (1024*1024):.2f} MB")
        print(f"Shared: {memory_info.shared / (1024*1024):.2f} MB")
        print(f"Text: {memory_info.text / (1024*1024):.2f} MB")
        print(f"Data: {memory_info.data / (1024*1024):.2f} MB")

        # Memory Maps
        print("\nMemory Maps:")
        for mmap in process.memory_maps(grouped=True):
            print(f"Path: {mmap.path}")
            print(f"  RSS: {mmap.rss / (1024*1024):.2f} MB")
            print(f"  Size: {mmap.size / (1024*1024):.2f} MB")

    except psutil.NoSuchProcess:
        print(f"Process {pid} does not exist")
    except psutil.AccessDenied:
        print("Access denied to process information")
    except Exception as e:
        print(f"An error occurred: {e}")


def thread_information():
    try:
        pid = int(input("Enter PID: "))
        process = psutil.Process(pid)

        print(f"\nThread Information for PID {pid} ({process.name()}):")
        threads = process.threads()

        print("\nID\tUser Time\tSystem Time")
        print("-" * 40)
        for thread in threads:
            print(f"{thread.id}\t{thread.user_time:.2f}s\t{thread.system_time:.2f}s")

    except psutil.NoSuchProcess:
        print(f"Process {pid} does not exist")
    except psutil.AccessDenied:
        print("Access denied to process information")
    except Exception as e:
        print(f"An error occurred: {e}")


def process_memory_maps():
    try:
        pid = int(input("Enter PID: "))
        process = psutil.Process(pid)

        print(f"\nMemory Maps for PID {pid} ({process.name()}):")
        maps = process.memory_maps(grouped=True)

        print("\nPath\tRSS\tSize\tPermissions")
        print("-" * 70)
        for mmap in maps:
            perms = (
                f"{'r' if mmap.perms[0] == 'r' else '-'}"
                f"{'w' if mmap.perms[1] == 'w' else '-'}"
                f"{'x' if mmap.perms[2] == 'x' else '-'}"
            )
            print(
                f"{mmap.path[:30]}\t{mmap.rss/(1024*1024):.1f}MB\t{mmap.size/(1024*1024):.1f}MB\t{perms}"
            )

    except psutil.NoSuchProcess:
        print(f"Process {pid} does not exist")
    except psutil.AccessDenied:
        print("Access denied to process information")
    except Exception as e:
        print(f"An error occurred: {e}")


# --- Scheduled Tasks Functions ---
def scheduled_tasks():
    while True:
        print("\n--- Scheduled Tasks Management ---")
        print("1. List All Cron Jobs")
        print("2. Add Cron Job")
        print("3. Remove Cron Job")
        print("4. Enable Cron Job")
        print("5. Disable Cron Job")
        print("6. Edit Cron Job")
        print("7. Show Cron Job Status")
        print("8. Import Cron Jobs")
        print("9. Export Cron Jobs")
        print("0. Back to Main Menu")
        choice = input("Select an option: ")

        if choice == "1":
            list_cron_jobs()
        elif choice == "2":
            add_cron_job()
        elif choice == "3":
            remove_cron_job()
        elif choice == "4":
            enable_cron_job()
        elif choice == "5":
            disable_cron_job()
        elif choice == "6":
            edit_cron_job()
        elif choice == "7":
            show_cron_status()
        elif choice == "8":
            import_cron_jobs()
        elif choice == "9":
            export_cron_jobs()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def list_cron_jobs():
    try:
        user = input("Enter username (leave empty for current user): ") or None
        cron = CronTab(user=user)

        print("\nCurrent Cron Jobs:")
        print("NUM\tSTATUS\tSCHEDULE\t\tCOMMAND")
        print("-" * 70)
        for i, job in enumerate(cron):
            status = "Enabled" if job.is_enabled() else "Disabled"
            print(f"{i}\t{status}\t{job.slices}\t{job.command[:30]}")

    except Exception as e:
        print(f"An error occurred: {e}")


def add_cron_job():
    try:
        user = input("Enter username (leave empty for current user): ") or None
        cron = CronTab(user=user)

        command = input("Enter command to schedule: ")
        comment = input("Enter comment/description: ")

        print("\nSchedule Options:")
        print("1. Simple Schedule (e.g., @daily, @hourly)")
        print("2. Custom Schedule (e.g., */5 * * * *)")
        choice = input("Select option: ")

        if choice == "1":
            print("\nAvailable schedules:")
            print("@yearly, @monthly, @weekly, @daily, @hourly")
            schedule = input("Enter schedule: ")
        else:
            minute = input("Minute (0-59, */5, *): ")
            hour = input("Hour (0-23, */2, *): ")
            day = input("Day of month (1-31, *): ")
            month = input("Month (1-12, *): ")
            day_of_week = input("Day of week (0-6, *): ")
            schedule = f"{minute} {hour} {day} {month} {day_of_week}"

        job = cron.new(command=command, comment=comment)
        job.setall(schedule)

        if job.is_valid():
            cron.write()
            print("Cron job added successfully")
            log_activity(f"Added cron job: {command}")
        else:
            print("Invalid cron schedule")

    except Exception as e:
        print(f"An error occurred: {e}")


def remove_cron_job():
    try:
        confirm = input(
            f"Are you sure you want to remove this job: '{job.command}'? (y/n): "
        )
        if confirm.lower() == "y":
            cron.remove(job)
            cron.write()
            print("Cron job removed successfully")
            log_activity(f"Removed cron job: {job.command}")
        else:
            print("Invalid job number")

    except Exception as e:
        print(f"An error occurred: {e}")


def enable_cron_job():
    try:
        user = input("Enter username (leave empty for current user): ") or None
        cron = CronTab(user=user)

        list_cron_jobs()
        job_num = int(input("\nEnter job number to enable: "))

        jobs = list(cron)
        if 0 <= job_num < len(jobs):
            job = jobs[job_num]
            job.enable()
            cron.write()
            print("Cron job enabled successfully")
            log_activity(f"Enabled cron job: {job.command}")
        else:
            print("Invalid job number")
    except Exception as e:
        print(f"An error occurred: {e}")


def disable_cron_job():
    try:
        user = input("Enter username (leave empty for current user): ") or None
        cron = CronTab(user=user)

        list_cron_jobs()
        job_num = int(input("\nEnter job number to disable: "))

        jobs = list(cron)
        if 0 <= job_num < len(jobs):
            job = jobs[job_num]
            job.enable(False)
            cron.write()
            print("Cron job disabled successfully")
            log_activity(f"Disabled cron job: {job.command}")
        else:
            print("Invalid job number")
    except Exception as e:
        print(f"An error occurred: {e}")


def edit_cron_job():
    try:
        user = input("Enter username (leave empty for current user): ") or None
        cron = CronTab(user=user)

        list_cron_jobs()
        job_num = int(input("\nEnter job number to edit: "))

        jobs = list(cron)
        if 0 <= job_num < len(jobs):
            job = jobs[job_num]

            print("\nCurrent job details:")
            print(f"Command: {job.command}")
            print(f"Schedule: {job.slices}")
            print(f"Comment: {job.comment}")

            print("\nWhat would you like to edit?")
            print("1. Command")
            print("2. Schedule")
            print("3. Comment")
            choice = input("Select option: ")

            if choice == "1":
                new_command = input("Enter new command: ")
                job.command = new_command
            elif choice == "2":
                print("\nSchedule Options:")
                print("1. Simple Schedule (e.g., @daily, @hourly)")
                print("2. Custom Schedule (e.g., */5 * * * *)")
                schedule_choice = input("Select option: ")

                if schedule_choice == "1":
                    print("\nAvailable schedules:")
                    print("@yearly, @monthly, @weekly, @daily, @hourly")
                    schedule = input("Enter schedule: ")
                else:
                    minute = input("Minute (0-59, */5, *): ")
                    hour = input("Hour (0-23, */2, *): ")
                    day = input("Day of month (1-31, *): ")
                    month = input("Month (1-12, *): ")
                    day_of_week = input("Day of week (0-6, *): ")
                    schedule = f"{minute} {hour} {day} {month} {day_of_week}"

                job.setall(schedule)
            elif choice == "3":
                new_comment = input("Enter new comment: ")
                job.comment = new_comment

            if job.is_valid():
                cron.write()
                print("Cron job updated successfully")
                log_activity(f"Updated cron job: {job.command}")
            else:
                print("Invalid cron job configuration")
        else:
            print("Invalid job number")
    except Exception as e:
        print(f"An error occurred: {e}")


def show_cron_status():
    try:
        # Check cron service status
        print("\nCron Service Status:")
        subprocess.run(["systemctl", "status", "cron"])

        # Show last cron runs
        print("\nLast Cron Job Executions:")
        subprocess.run(
            ["grep", "CRON", "/var/log/syslog", "|", "tail", "-n", "10"], shell=True
        )

        # Show cron configuration
        print("\nCron Configuration:")
        subprocess.run(["cat", "/etc/crontab"])
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def import_cron_jobs():
    try:
        file_path = input("Enter path to cron jobs file: ")
        user = input("Enter username (leave empty for current user): ") or None

        if not os.path.exists(file_path):
            print("File not found")
            return

        cron = CronTab(user=user)

        with open(file_path, "r") as f:
            content = f.read()

        # Backup current crontab
        backup_file = (
            f"/tmp/crontab_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        cron.write(backup_file)
        print(f"Current crontab backed up to {backup_file}")

        # Import new jobs
        cron = CronTab(tab=content)
        cron.write()
        print("Cron jobs imported successfully")
        log_activity(f"Imported cron jobs from {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

        # Restore from backup if available
        if "backup_file" in locals():
            restore = input("Would you like to restore from backup? (y/n): ")
            if restore.lower() == "y":
                try:
                    cron = CronTab(tabfile=backup_file)
                    cron.write()
                    print("Restored from backup successfully")
                except Exception as e:
                    print(f"Failed to restore from backup: {e}")


def export_cron_jobs():
    try:
        user = input("Enter username (leave empty for current user): ") or None
        export_path = input("Enter export file path: ")

        cron = CronTab(user=user)

        # Export to file
        cron.write(export_path)
        print(f"Cron jobs exported to {export_path}")
        log_activity(f"Exported cron jobs to {export_path}")

        # Show summary
        print("\nExported Jobs Summary:")
        with open(export_path, "r") as f:
            print(f.read())
    except Exception as e:
        print(f"An error occurred: {e}")


# --- Cron Job Validation Functions ---
def validate_cron_schedule(schedule):
    """Validate cron schedule format"""
    try:
        parts = schedule.split()
        if len(parts) != 5 and not schedule.startswith("@"):
            return False

        if schedule.startswith("@"):
            valid_special = [
                "@yearly",
                "@monthly",
                "@weekly",
                "@daily",
                "@hourly",
                "@reboot",
            ]
            return schedule in valid_special

        minute, hour, day, month, day_of_week = parts

        def check_field(field, min_val, max_val):
            if field == "*":
                return True
            if "/" in field:
                step = field.split("/")[1]
                return step.isdigit()
            if "-" in field:
                start, end = field.split("-")
                return (
                    start.isdigit()
                    and end.isdigit()
                    and min_val <= int(start) <= max_val
                    and min_val <= int(end) <= max_val
                )
            if "," in field:
                values = field.split(",")
                return all(v.isdigit() and min_val <= int(v) <= max_val for v in values)
            return field.isdigit() and min_val <= int(field) <= max_val

        return (
            check_field(minute, 0, 59)
            and check_field(hour, 0, 23)
            and check_field(day, 1, 31)
            and check_field(month, 1, 12)
            and check_field(day_of_week, 0, 6)
        )
    except Exception:
        return False


def check_cron_job(command, schedule):
    """Check if a cron job command and schedule are valid"""
    issues = []

    # Check schedule
    if not validate_cron_schedule(schedule):
        issues.append("Invalid cron schedule format")

    # Check command
    if not command:
        issues.append("Empty command")
    elif command.startswith("rm"):
        issues.append("Warning: Command contains file deletion")
    elif ";" in command or "&&" in command:
        issues.append("Warning: Command contains multiple commands")

    # Check if command exists
    command_path = command.split()[0]
    if not shutil.which(command_path):
        issues.append(f"Command '{command_path}' not found in PATH")

    return issues


def suggest_cron_schedule():
    """Suggest common cron schedules"""
    print("\nCommon Cron Schedule Patterns:")
    print("1. Every minute: * * * * *")
    print("2. Every hour: 0 * * * *")
    print("3. Every day at midnight: 0 0 * * *")
    print("4. Every Sunday at midnight: 0 0 * * 0")
    print("5. Every first day of month: 0 0 1 * *")
    print("6. Every 15 minutes: */15 * * * *")
    print("7. Weekdays at 9 AM: 0 9 * * 1-5")
    print("8. Every 4 hours: 0 */4 * * *")

    choice = input("\nSelect a pattern (or press Enter to skip): ")
    schedules = {
        "1": "* * * * *",
        "2": "0 * * * *",
        "3": "0 0 * * *",
        "4": "0 0 * * 0",
        "5": "0 0 1 * *",
        "6": "*/15 * * * *",
        "7": "0 9 * * 1-5",
        "8": "0 */4 * * *",
    }
    return schedules.get(choice, "")


# --- Package Management Functions ---
def package_management():
    while True:
        print("\n--- Package Management ---")
        print("1. Update Package List")
        print("2. Upgrade All Packages")
        print("3. Install Package")
        print("4. Remove Package")
        print("5. Search Package")
        print("6. Show Package Info")
        print("7. List Installed Packages")
        print("8. Clean Package Cache")
        print("9. Add Repository")
        print("10. Manage Package Sources")
        print("11. Check Package Dependencies")
        print("12. Fix Broken Packages")
        print("0. Back to Main Menu")

        choice = input("Select an option: ")

        if choice == "1":
            update_packages()
        elif choice == "2":
            upgrade_packages()
        elif choice == "3":
            install_package()
        elif choice == "4":
            remove_package()
        elif choice == "5":
            search_package()
        elif choice == "6":
            show_package_info()
        elif choice == "7":
            list_installed_packages()
        elif choice == "8":
            clean_package_cache()
        elif choice == "9":
            add_repository()
        elif choice == "10":
            manage_sources()
        elif choice == "11":
            check_dependencies()
        elif choice == "12":
            fix_broken_packages()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def update_packages():
    try:
        print("Updating package lists...")
        subprocess.run(["sudo", "apt", "update"], check=True)

        # Check for updates
        print("\nChecking for updates...")
        output = subprocess.run(
            ["apt", "list", "--upgradable"], capture_output=True, text=True
        ).stdout

        if "Listing..." in output and len(output.split("\n")) > 2:
            print("\nAvailable updates:")
            print(output)
        else:
            print("All packages are up to date.")

        log_activity("Updated package lists")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def upgrade_packages():
    try:
        print("Checking available upgrades...")

        # Show potential upgrades first
        subprocess.run(["apt", "list", "--upgradable"])

        upgrade_type = input(
            "\nPerform (n)ormal or (d)istribution upgrade? (n/d): "
        ).lower()

        if upgrade_type == "d":
            confirm = input(
                "Distribution upgrade can make significant changes. Continue? (y/n): "
            )
            if confirm.lower() == "y":
                subprocess.run(["sudo", "apt", "dist-upgrade", "-y"], check=True)
                log_activity("Performed distribution upgrade")
        else:
            subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)
            log_activity("Performed system upgrade")

        print("\nUpgrade completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def install_package():
    try:
        package = input("Enter package name to install: ")

        # Check if package exists
        check = subprocess.run(
            ["apt-cache", "show", package], capture_output=True, text=True
        )

        if check.returncode != 0:
            print(f"Package '{package}' not found.")

            # Search for similar packages
            print("\nSimilar packages:")
            subprocess.run(["apt-cache", "search", package])
            return

        # Show package information before installing
        print("\nPackage information:")
        subprocess.run(["apt-cache", "show", package])

        confirm = input("\nProceed with installation? (y/n): ")
        if confirm.lower() == "y":
            subprocess.run(["sudo", "apt", "install", "-y", package], check=True)
            print(f"\nPackage '{package}' installed successfully.")
            log_activity(f"Installed package: {package}")

            # Check if any recommended packages were not installed
            recommended = subprocess.run(
                ["apt-cache", "depends", package, "|", "grep", "Recommends"],
                shell=True,
                capture_output=True,
                text=True,
            ).stdout

            if recommended:
                print("\nRecommended packages:")
                print(recommended)
                install_recommended = input("Install recommended packages? (y/n): ")
                if install_recommended.lower() == "y":
                    subprocess.run(
                        ["sudo", "apt", "install", "--install-recommends", package],
                        check=True,
                    )

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def remove_package():
    try:
        package = input("Enter package name to remove: ")

        # Check if package is installed
        check = subprocess.run(["dpkg", "-l", package], capture_output=True, text=True)

        if "no packages found matching" in check.stderr.lower():
            print(f"Package '{package}' is not installed.")
            return

        print("\nRemoval options:")
        print("1. Remove package only")
        print("2. Remove package and configuration files (purge)")
        print("3. Remove package and unused dependencies")
        choice = input("Select option: ")

        if choice == "1":
            subprocess.run(["sudo", "apt", "remove", "-y", package], check=True)
        elif choice == "2":
            subprocess.run(["sudo", "apt", "purge", "-y", package], check=True)
        elif choice == "3":
            subprocess.run(
                ["sudo", "apt", "autoremove", "--purge", "-y", package], check=True
            )

        print(f"\nPackage '{package}' removed successfully.")
        log_activity(f"Removed package: {package}")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def search_package():
    try:
        search_term = input("Enter search term: ")
        search_type = input("Search in (n)ame only or (d)escription? (n/d): ").lower()

        if search_type == "n":
            print("\nSearching package names...")
            subprocess.run(["apt-cache", "search", f"^{search_term}"])
        else:
            print("\nSearching package names and descriptions...")
            subprocess.run(["apt-cache", "search", search_term])

        # Show additional details for exact matches
        exact_match = subprocess.run(
            ["apt-cache", "show", search_term], capture_output=True, text=True
        )
        if exact_match.returncode == 0:
            print("\nExact match found:")
            print(exact_match.stdout)

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def show_package_info():
    try:
        package = input("Enter package name: ")

        print("\nPackage information:")
        subprocess.run(["apt-cache", "show", package])

        # Check if package is installed
        print("\nInstallation status:")
        subprocess.run(["dpkg", "-l", package])

        # Show dependencies
        print("\nDependencies:")
        subprocess.run(["apt-cache", "depends", package])

        # Show reverse dependencies
        print("\nReverse dependencies (packages that depend on this):")
        subprocess.run(["apt-cache", "rdepends", package])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def list_installed_packages():
    try:
        sort_by = input("Sort by (n)ame or (s)ize? (n/s): ").lower()

        if sort_by == "s":
            print("\nInstalled packages by size:")
            subprocess.run(
                """dpkg-query -W -f='${Installed-Size}\t${Package}\n' | sort -n""",
                shell=True,
            )
        else:
            print("\nInstalled packages:")
            subprocess.run(["dpkg", "--get-selections"])

        # Show summary
        total = subprocess.run(
            ["dpkg", "--get-selections", "|", "wc", "-l"],
            shell=True,
            capture_output=True,
            text=True,
        )
        print(f"\nTotal installed packages: {total.stdout.strip()}")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def clean_package_cache():
    try:
        print("Package cache size before cleaning:")
        subprocess.run(["du", "-sh", "/var/cache/apt/archives"])

        print("\nCleaning options:")
        print("1. Clean outdated packages")
        print("2. Clean all cached packages")
        print("3. Clean unused dependencies")
        choice = input("Select option: ")

        if choice == "1":
            subprocess.run(["sudo", "apt", "autoclean"], check=True)
        elif choice == "2":
            subprocess.run(["sudo", "apt", "clean"], check=True)
        elif choice == "3":
            subprocess.run(["sudo", "apt", "autoremove", "-y"], check=True)

        print("\nPackage cache size after cleaning:")
        subprocess.run(["du", "-sh", "/var/cache/apt/archives"])
        log_activity("Cleaned package cache")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def add_repository():
    try:
        print("\nAdd Repository Options:")
        print("1. Add PPA repository")
        print("2. Add custom repository")
        print("3. Import repository key")
        choice = input("Select option: ")

        if choice == "1":
            ppa = input("Enter PPA (e.g., ppa:user/repo): ")
            subprocess.run(["sudo", "add-apt-repository", "-y", ppa], check=True)

        elif choice == "2":
            repo_line = input("Enter repository line: ")
            with open("/etc/apt/sources.list.d/custom.list", "a") as f:
                f.write(f"\n{repo_line}")

        elif choice == "3":
            key_url = input("Enter key URL or fingerprint: ")
            if key_url.startswith("http"):
                subprocess.run(
                    ["curl", "-fsSL", key_url, "|", "sudo", "apt-key", "add", "-"],
                    shell=True,
                    check=True,
                )
            else:
                subprocess.run(
                    [
                        "sudo",
                        "apt-key",
                        "adv",
                        "--keyserver",
                        "keyserver.ubuntu.com",
                        "--recv-keys",
                        key_url,
                    ],
                    check=True,
                )

        print("\nUpdating package lists with new repository...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        log_activity("Added new repository")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def manage_sources():
    try:
        while True:
            print("\n--- Package Sources Management ---")
            print("1. Show enabled sources")
            print("2. Enable/Disable source")
            print("3. Edit sources file")
            print("4. Backup sources")
            print("5. Restore sources")
            print("0. Back")

            choice = input("Select option: ")

            if choice == "1":
                print("\nEnabled sources:")
                with open("/etc/apt/sources.list", "r") as f:
                    sources = f.readlines()
                for i, source in enumerate(sources):
                    if not source.strip().startswith("#") and source.strip():
                        print(f"{i}: {source.strip()}")

            elif choice == "2":
                source_num = input("Enter source number to toggle: ")
                try:
                    with open("/etc/apt/sources.list", "r") as f:
                        sources = f.readlines()

                    if sources[int(source_num)].startswith("#"):
                        sources[int(source_num)] = sources[int(source_num)][1:]
                    else:
                        sources[int(source_num)] = "#" + sources[int(source_num)]

                    with open("/etc/apt/sources.list", "w") as f:
                        f.writelines(sources)

                except (IndexError, ValueError):
                    print("Invalid source number")

            elif choice == "3":
                subprocess.run(["sudo", "nano", "/etc/apt/sources.list"])

            elif choice == "4":
                backup_file = f"/etc/apt/sources.list.backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2("/etc/apt/sources.list", backup_file)
                print(f"Backup created: {backup_file}")

            elif choice == "5":
                backups = glob.glob("/etc/apt/sources.list.backup_*")
                if backups:
                    print("\nAvailable backups:")
                    for i, backup in enumerate(backups):
                        print(f"{i}: {backup}")
                    backup_num = input("Enter backup number to restore: ")
                    try:
                        shutil.copy2(backups[int(backup_num)], "/etc/apt/sources.list")
                        print("Sources restored from backup")
                    except (IndexError, ValueError):
                        print("Invalid backup number")
                else:
                    print("No backups found")

            elif choice == "0":
                break

    except Exception as e:
        print(f"An error occurred: {e}")


def check_dependencies():
    try:
        package = input("Enter package name to check dependencies: ")

        print("\nDirect dependencies:")
        subprocess.run(["apt-cache", "depends", package])

        print("\nReverse dependencies:")
        subprocess.run(["apt-cache", "rdepends", package])

        print("\nChecking for broken dependencies...")
        subprocess.run(["sudo", "apt", "check"])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def fix_broken_packages():
    try:
        print("Checking for broken packages...")

        # Run package configuration
        subprocess.run(["sudo", "dpkg", "--configure", "-a"], check=True)

        # Fix broken dependencies
        subprocess.run(["sudo", "apt", "--fix-broken", "install"], check=True)

        # Clean up
        subprocess.run(["sudo", "apt", "autoremove"], check=True)

        print("\nPackage system repair completed.")
        log_activity("Fixed broken packages")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


# --- Log Management Functions ---
def log_management():
    while True:
        print("\n--- Log Management ---")
        print("1. View System Logs")
        print("2. View Authentication Logs")
        print("3. View Application Logs")
        print("4. Monitor Logs Real-time")
        print("5. Search in Logs")
        print("6. Analyze Logs")
        print("7. Rotate Logs")
        print("8. Clean Old Logs")
        print("9. Configure Logging")
        print("10. Export Logs")
        print("0. Back to Main Menu")

        choice = input("Select an option: ")

        if choice == "1":
            view_system_logs()
        elif choice == "2":
            view_auth_logs()
        elif choice == "3":
            view_app_logs()
        elif choice == "4":
            monitor_logs()
        elif choice == "5":
            search_logs()
        elif choice == "6":
            analyze_logs()
        elif choice == "7":
            rotate_logs()
        elif choice == "8":
            clean_old_logs()
        elif choice == "9":
            configure_logging()
        elif choice == "10":
            export_logs()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def view_system_logs():
    while True:
        print("\n--- System Logs ---")
        print("1. System Messages (syslog)")
        print("2. Kernel Log")
        print("3. Boot Log")
        print("4. Hardware Log")
        print("5. System Journal")
        print("0. Back")

        choice = input("Select log to view: ")
        lines = input("Enter number of lines to show (default: 50): ") or "50"

        try:
            if choice == "1":
                subprocess.run(["tail", "-n", lines, "/var/log/syslog"])
            elif choice == "2":
                subprocess.run(["tail", "-n", lines, "/var/log/kern.log"])
            elif choice == "3":
                subprocess.run(["tail", "-n", lines, "/var/log/boot.log"])
            elif choice == "4":
                subprocess.run(["tail", "-n", lines, "/var/log/dmesg"])
            elif choice == "5":
                subprocess.run(["journalctl", "-n", lines])
            elif choice == "0":
                break
            else:
                print("Invalid option.")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")


def view_auth_logs():
    try:
        print("\n--- Authentication Logs ---")
        print("1. Recent login attempts")
        print("2. Failed login attempts")
        print("3. SSH access logs")
        print("4. sudo usage logs")
        print("0. Back")

        choice = input("Select option: ")

        if choice == "1":
            subprocess.run(["last", "-n", "20"])
        elif choice == "2":
            subprocess.run(["grep", "Failed password", "/var/log/auth.log"])
        elif choice == "3":
            subprocess.run(["grep", "sshd", "/var/log/auth.log"])
        elif choice == "4":
            subprocess.run(["grep", "sudo", "/var/log/auth.log"])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def view_app_logs():
    try:
        # List available application logs
        print("\nAvailable Application Logs:")
        logs = glob.glob("/var/log/*")
        for i, log in enumerate(logs):
            if os.path.isfile(log):
                print(f"{i}: {os.path.basename(log)}")

        log_num = input("\nEnter log number to view (or 'c' to enter custom path): ")

        if log_num.lower() == "c":
            log_path = input("Enter log file path: ")
        else:
            try:
                log_path = logs[int(log_num)]
            except (ValueError, IndexError):
                print("Invalid selection")
                return

        lines = input("Enter number of lines to show (default: 50): ") or "50"

        if os.path.exists(log_path):
            subprocess.run(["tail", "-n", lines, log_path])
        else:
            print("Log file not found")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def monitor_logs():
    try:
        print("\nAvailable logs to monitor:")
        print("1. System Log (syslog)")
        print("2. Authentication Log")
        print("3. Apache Access Log")
        print("4. Apache Error Log")
        print("5. Custom Log File")

        choice = input("Select log to monitor: ")

        log_file = {
            "1": "/var/log/syslog",
            "2": "/var/log/auth.log",
            "3": "/var/log/apache2/access.log",
            "4": "/var/log/apache2/error.log",
        }.get(choice)

        if choice == "5":
            log_file = input("Enter path to log file: ")

        if log_file and os.path.exists(log_file):
            print("Monitoring log (Press Ctrl+C to stop)...")
            subprocess.run(["tail", "-f", log_file])
        else:
            print("Log file not found")

    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def search_logs():
    try:
        print("\nSearch Options:")
        print("1. Search in all logs")
        print("2. Search in specific log")
        print("3. Search by date range")
        print("4. Advanced search")

        choice = input("Select search option: ")

        if choice == "1":
            pattern = input("Enter search pattern: ")
            subprocess.run(["grep", "-r", pattern, "/var/log/"])

        elif choice == "2":
            log_file = input("Enter log file path: ")
            pattern = input("Enter search pattern: ")
            subprocess.run(["grep", pattern, log_file])

        elif choice == "3":
            log_file = input("Enter log file path: ")
            start_date = input("Enter start date (YYYY-MM-DD): ")
            end_date = input("Enter end date (YYYY-MM-DD): ")
            pattern = input("Enter search pattern (optional): ")

            # Convert dates to seconds since epoch
            start_ts = datetime.datetime.strptime(start_date, "%Y-%m-%d").timestamp()
            end_ts = datetime.datetime.strptime(end_date, "%Y-%m-%d").timestamp()

            # Use awk to filter by date and pattern
            awk_cmd = f'awk \'$0 >= "{start_date}" && $0 <= "{end_date}"'
            if pattern:
                awk_cmd += f" && /{pattern}/"
            awk_cmd += "{print}'"

            subprocess.run(["awk", awk_cmd, log_file], shell=True)

        elif choice == "4":
            print("\nAdvanced Search Options:")
            print("1. Search with context")
            print("2. Search with regular expression")
            print("3. Case-insensitive search")

            adv_choice = input("Select option: ")
            log_file = input("Enter log file path: ")
            pattern = input("Enter search pattern: ")

            if adv_choice == "1":
                lines = input("Enter number of context lines: ")
                subprocess.run(["grep", "-C", lines, pattern, log_file])
            elif adv_choice == "2":
                subprocess.run(["grep", "-E", pattern, log_file])
            elif adv_choice == "3":
                subprocess.run(["grep", "-i", pattern, log_file])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    except ValueError as e:
        print(f"Invalid date format: {e}")


def analyze_logs():
    try:
        print("\nLog Analysis Options:")
        print("1. Error frequency analysis")
        print("2. IP address frequency")
        print("3. Resource usage patterns")
        print("4. Authentication failures")
        print("5. Custom pattern analysis")

        choice = input("Select analysis type: ")

        if choice == "1":
            log_file = input("Enter log file path: ")
            subprocess.run(
                "grep -i 'error\\|warning\\|critical\\|failed' "
                + f"{log_file} | sort | uniq -c | sort -nr",
                shell=True,
            )

        elif choice == "2":
            log_file = input("Enter log file path: ")
            subprocess.run(
                "grep -o '[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}' "
                + f"{log_file} | sort | uniq -c | sort -nr",
                shell=True,
            )

        elif choice == "3":
            print("\nAnalyzing system resource usage patterns...")
            subprocess.run(["sar", "-u", "1", "5"])  # CPU usage
            subprocess.run(["sar", "-r", "1", "5"])  # Memory usage
            subprocess.run(["sar", "-b", "1", "5"])  # I/O usage

        elif choice == "4":
            print("\nAnalyzing authentication failures...")
            subprocess.run(
                "grep 'authentication failure\\|Failed password' /var/log/auth.log | "
                + "awk '{print $1,$2,$3}' | sort | uniq -c | sort -nr",
                shell=True,
            )

        elif choice == "5":
            log_file = input("Enter log file path: ")
            pattern = input("Enter pattern to analyze: ")
            subprocess.run(
                f"grep '{pattern}' {log_file} | sort | uniq -c | sort -nr", shell=True
            )

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def rotate_logs():
    try:
        print("\nLog Rotation Options:")
        print("1. Rotate all logs now")
        print("2. Configure log rotation")
        print("3. Show rotation status")

        choice = input("Select option: ")

        if choice == "1":
            confirm = input("Force log rotation now? (y/n): ")
            if confirm.lower() == "y":
                subprocess.run(["sudo", "logrotate", "-f", "/etc/logrotate.conf"])
                print("Logs rotated successfully")

        elif choice == "2":
            print("\nEditing logrotate configuration...")
            subprocess.run(["sudo", "nano", "/etc/logrotate.conf"])

        elif choice == "3":
            print("\nLog Rotation Status:")
            subprocess.run(["logrotate", "-d", "/etc/logrotate.conf"])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def clean_old_logs():
    try:
        print("\nCleaning Options:")
        print("1. Clean logs older than specified days")
        print("2. Clean logs larger than specified size")
        print("3. Clean specific log files")

        choice = input("Select option: ")

        if choice == "1":
            days = input("Enter number of days: ")
            confirm = input(f"Clean logs older than {days} days? (y/n): ")
            if confirm.lower() == "y":
                subprocess.run(
                    f"find /var/log -type f -mtime +{days} -delete", shell=True
                )
                print("Old logs cleaned successfully")

        elif choice == "2":
            size = input("Enter size in MB: ")
            confirm = input(f"Clean logs larger than {size}MB? (y/n): ")
            if confirm.lower() == "y":
                subprocess.run(
                    f"find /var/log -type f -size +{size}M -delete", shell=True
                )
                print("Large logs cleaned successfully")

        elif choice == "3":
            print("\nAvailable log files:")
            subprocess.run(["ls", "-lh", "/var/log/"])
            log_file = input("Enter log file name to clean: ")
            confirm = input(f"Clean {log_file}? (y/n): ")
            if confirm.lower() == "y":
                subprocess.run(["sudo", "truncate", "-s", "0", f"/var/log/{log_file}"])
                print("Log file cleaned successfully")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def configure_logging():
    try:
        while True:
            print("\n--- Logging Configuration ---")
            print("1. Configure syslog")
            print("2. Configure journal")
            print("3. Configure log retention")
            print("4. Configure log permissions")
            print("0. Back")

            choice = input("Select option: ")

            if choice == "1":
                subprocess.run(["sudo", "nano", "/etc/rsyslog.conf"])

            elif choice == "2":
                subprocess.run(["sudo", "nano", "/etc/systemd/journald.conf"])

            elif choice == "3":
                print("\nCurrent log retention settings:")
                subprocess.run(["cat", "/etc/logrotate.conf"])
                edit = input("\nEdit retention settings? (y/n): ")
                if edit.lower() == "y":
                    subprocess.run(["sudo", "nano", "/etc/logrotate.conf"])

            elif choice == "4":
                print("\nCurrent log permissions:")
                subprocess.run(["ls", "-l", "/var/log"])
                file = input("\nEnter log file to modify permissions: ")
                if os.path.exists(f"/var/log/{file}"):
                    perms = input("Enter new permissions (e.g., 644): ")
                    subprocess.run(["sudo", "chmod", perms, f"/var/log/{file}"])

            elif choice == "0":
                break

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def export_logs():
    try:
        os.makedirs(export_dir, exist_ok=True)

        # Find and export logs within date range
        cmd = f"""find /var/log -type f -newermt "{start_date}" ! -newermt "{end_date}" -exec cp {{}} {export_dir} \;"""
        subprocess.run(cmd, shell=True)

        # Create archive of exported logs
        archive_name = f"logs_{start_date}_to_{end_date}.tar.gz"
        subprocess.run(["tar", "czf", archive_name, export_dir])

        print(f"Logs exported to {archive_name}")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    except ValueError as e:
        print(f"Invalid date format: {e}")


# --- System Maintenance Functions ---
def system_maintenance():
    while True:
        print("\n--- System Maintenance ---")
        print("1. System Cleanup")
        print("2. System Health Check")
        print("3. System Optimization")
        print("4. Disk Maintenance")
        print("5. System Updates")
        print("6. Service Maintenance")
        print("7. Security Maintenance")
        print("8. Backup Maintenance")
        print("9. Schedule Maintenance Tasks")
        print("0. Back to Main Menu")

        choice = input("Select an option: ")

        if choice == "1":
            system_cleanup()
        elif choice == "2":
            system_health_check()
        elif choice == "3":
            system_optimization()
        elif choice == "4":
            disk_maintenance()
        elif choice == "5":
            system_updates()
        elif choice == "6":
            service_maintenance()
        elif choice == "7":
            security_maintenance()
        elif choice == "8":
            backup_maintenance()
        elif choice == "9":
            schedule_maintenance()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def system_cleanup():
    try:
        print("\n--- System Cleanup ---")
        print("Running system cleanup tasks...")

        # Clean package cache
        print("\n1. Cleaning package cache...")
        subprocess.run(["sudo", "apt", "clean"], check=True)
        subprocess.run(["sudo", "apt", "autoclean"], check=True)

        # Remove old kernels
        print("\n2. Removing old kernels...")
        subprocess.run(["sudo", "apt", "autoremove", "--purge"], check=True)

        # Clean temporary files
        print("\n3. Cleaning temporary files...")
        subprocess.run(["sudo", "rm", "-rf", "/tmp/*"], check=True)
        subprocess.run(["sudo", "rm", "-rf", "/var/tmp/*"], check=True)

        # Clean journal logs
        print("\n4. Cleaning journal logs...")
        subprocess.run(["sudo", "journalctl", "--vacuum-time=7d"], check=True)

        # Clean user cache
        print("\n5. Cleaning user cache...")
        subprocess.run(["rm", "-rf", f"{os.path.expanduser('~')}/.cache/*"], check=True)

        # Clean thumbnail cache
        print("\n6. Cleaning thumbnail cache...")
        subprocess.run(
            ["rm", "-rf", f"{os.path.expanduser('~')}/.thumbnails/*"], check=True
        )

        # Clean bash history
        print("\n7. Truncating bash history...")
        subprocess.run(
            ["truncate", "-s", "0", f"{os.path.expanduser('~')}/.bash_history"],
            check=True,
        )

        print("\nSystem cleanup completed successfully.")
        log_activity("Performed system cleanup")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def system_health_check():
    try:
        print("\n--- System Health Check ---")

        # Check disk space
        print("\n1. Checking disk space...")
        subprocess.run(["df", "-h"])

        # Check memory usage
        print("\n2. Checking memory usage...")
        memory = psutil.virtual_memory()
        print(f"Total: {memory.total / (1024**3):.2f} GB")
        print(f"Used: {memory.used / (1024**3):.2f} GB ({memory.percent}%)")
        print(f"Available: {memory.available / (1024**3):.2f} GB")

        # Check CPU load
        print("\n3. Checking CPU load...")
        load1, load5, load15 = os.getloadavg()
        cpu_count = psutil.cpu_count()
        print(
            f"Load averages: 1min: {load1:.2f}, 5min: {load5:.2f}, 15min: {load15:.2f}"
        )
        print(f"CPU cores: {cpu_count}")

        # Check system services
        print("\n4. Checking system services...")
        subprocess.run(["systemctl", "--failed"])

        # Check for system errors
        print("\n5. Checking system logs for errors...")
        subprocess.run(["sudo", "journalctl", "-p", "3", "-xn", "10"])

        # Check disk health
        print("\n6. Checking disk health...")
        disks = psutil.disk_partitions()
        for disk in disks:
            if disk.device.startswith("/dev/sd"):
                print(f"\nChecking {disk.device}:")
                subprocess.run(["sudo", "smartctl", "-H", disk.device])

        # Check network connectivity
        print("\n7. Checking network connectivity...")
        subprocess.run(["ping", "-c", "4", "8.8.8.8"])

        # Check system updates
        print("\n8. Checking for system updates...")
        subprocess.run(["sudo", "apt", "update", "-qq"])
        subprocess.run(["apt", "list", "--upgradable"])

        print("\nSystem health check completed.")
        log_activity("Performed system health check")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def system_optimization():
    try:
        print("\n--- System Optimization ---")

        # Optimize package database
        print("\n1. Optimizing package database...")
        subprocess.run(["sudo", "apt", "clean"], check=True)
        subprocess.run(["sudo", "apt", "autoclean"], check=True)

        # Optimize file system
        print("\n2. Optimizing file systems...")
        for partition in psutil.disk_partitions():
            if partition.fstype == "ext4":
                print(f"Optimizing {partition.mountpoint}...")
                subprocess.run(["sudo", "e4defrag", partition.mountpoint], check=True)

        # Optimize system services
        print("\n3. Analyzing and optimizing system services...")
        subprocess.run(["systemd-analyze"])
        subprocess.run(["systemd-analyze", "blame"])

        # Optimize memory
        print("\n4. Optimizing memory usage...")
        subprocess.run(["sudo", "sysctl", "vm.drop_caches=3"], check=True)

        # Optimize swap usage
        print("\n5. Optimizing swap usage...")
        swappiness = (
            input("Enter desired swappiness value (0-100, default=60): ") or "60"
        )
        subprocess.run(["sudo", "sysctl", f"vm.swappiness={swappiness}"], check=True)

        # Optimize network settings
        print("\n6. Optimizing network settings...")
        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.tcp_timestamps=1"], check=True
        )
        subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.tcp_sack=1"], check=True)

        print("\nSystem optimization completed.")
        log_activity("Performed system optimization")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def disk_maintenance():
    try:
        print("\n--- Disk Maintenance ---")

        # List available disks
        print("\nAvailable disks:")
        subprocess.run(["lsblk"])

        while True:
            print("\nMaintenance Options:")
            print("1. Check filesystem")
            print("2. Repair filesystem")
            print("3. Check disk health")
            print("4. Optimize disk")
            print("5. Scan for bad blocks")
            print("0. Back")

            choice = input("Select option: ")

            if choice == "1":
                disk = input("Enter disk partition (e.g., /dev/sda1): ")
                print("\nChecking filesystem...")
                subprocess.run(["sudo", "fsck", "-n", disk])

            elif choice == "2":
                disk = input("Enter disk partition (e.g., /dev/sda1): ")
                print("\nWARNING: Filesystem repair requires unmounting the partition!")
                confirm = input("Continue? (y/n): ")
                if confirm.lower() == "y":
                    subprocess.run(["sudo", "fsck", "-f", "-y", disk])

            elif choice == "3":
                disk = input("Enter disk device (e.g., /dev/sda): ")
                print("\nChecking disk health...")
                subprocess.run(["sudo", "smartctl", "-H", disk])
                subprocess.run(["sudo", "smartctl", "-A", disk])

            elif choice == "4":
                disk = input("Enter disk partition (e.g., /dev/sda1): ")
                print("\nOptimizing disk...")
                subprocess.run(["sudo", "e4defrag", disk])

            elif choice == "5":
                disk = input("Enter disk device (e.g., /dev/sda): ")
                print("\nWARNING: Bad blocks scan can take a long time!")
                confirm = input("Continue? (y/n): ")
                if confirm.lower() == "y":
                    subprocess.run(["sudo", "badblocks", "-v", disk])

            elif choice == "0":
                break

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def system_updates():
    try:
        print("\n--- System Updates ---")

        # Check for updates
        print("\n1. Checking for updates...")
        subprocess.run(["sudo", "apt", "update"], check=True)

        # List available updates
        print("\n2. Available updates:")
        subprocess.run(["apt", "list", "--upgradable"])

        # Prompt for update type
        print("\nUpdate Options:")
        print("1. Security updates only")
        print("2. All updates")
        print("3. Distribution upgrade")

        choice = input("Select update type: ")

        if choice == "1":
            subprocess.run(["sudo", "unattended-upgrade", "--debug"], check=True)
        elif choice == "2":
            subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)
        elif choice == "3":
            print("\nWARNING: Distribution upgrade can make significant changes!")
            confirm = input("Continue? (y/n): ")
            if confirm.lower() == "y":
                subprocess.run(["sudo", "apt", "dist-upgrade", "-y"], check=True)

        # Clean up
        print("\nCleaning up...")
        subprocess.run(["sudo", "apt", "autoremove", "-y"], check=True)
        subprocess.run(["sudo", "apt", "clean"], check=True)

        print("\nSystem updates completed.")
        log_activity("Performed system updates")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def service_maintenance():
    try:
        print("\n--- Service Maintenance ---")

        while True:
            print("\nMaintenance Options:")
            print("1. List all services")
            print("2. Check failed services")
            print("3. Restart service")
            print("4. Clean service logs")
            print("5. Analyze service usage")
            print("0. Back")

            choice = input("Select option: ")

            if choice == "1":
                subprocess.run(["systemctl", "list-units", "--type=service"])

            elif choice == "2":
                subprocess.run(["systemctl", "--failed"])

            elif choice == "3":
                service = input("Enter service name: ")
                confirm = input(f"Restart {service}? (y/n): ")
                if confirm.lower() == "y":
                    subprocess.run(["sudo", "systemctl", "restart", service])

            elif choice == "4":
                service = input("Enter service name: ")
                subprocess.run(
                    ["sudo", "journalctl", "--vacuum-time=2d", "-u", service]
                )

            elif choice == "5":
                print("\nAnalyzing service boot times...")
                subprocess.run(["systemd-analyze", "blame"])

            elif choice == "0":
                break

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def security_maintenance():
    try:
        print("\n--- Security Maintenance ---")

        # Check system updates
        print("\n1. Checking for security updates...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["apt", "list", "--upgradable"], check=True)

        # Check running services
        print("\n2. Checking running services...")
        subprocess.run(["ss", "-tulpn"])

        # Check login attempts
        print("\n3. Checking recent login attempts...")
        subprocess.run(["lastb", "-n", "10"])

        # Check system integrity
        print("\n4. Checking system integrity...")
        subprocess.run(["sudo", "aide", "--check"])

        # Update security policies
        print("\n5. Updating security policies...")
        subprocess.run(["sudo", "update-apparmor"])

        print("\nSecurity maintenance completed.")
        log_activity("Performed security maintenance")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def backup_maintenance():
    try:
        print("\n--- Backup Maintenance ---")

        while True:
            print("\nMaintenance Options:")
            print("1. List backups")
            print("2. Verify backup integrity")
            print("3. Clean old backups")
            print("4. Create new backup")
            print("0. Back")

            choice = input("Select option: ")

            if choice == "1":
                backup_dir = input("Enter backup directory: ")
                print("\nAvailable backups:")
                subprocess.run(["ls", "-lh", backup_dir])

            elif choice == "2":
                backup_file = input("Enter backup file path: ")
                print("\nVerifying backup integrity...")
                if backup_file.endswith(".tar.gz"):
                    subprocess.run(["tar", "-tzf", backup_file])
                else:
                    print("Unsupported backup format")

            elif choice == "3":
                backup_dir = input("Enter backup directory: ")
                days = input("Remove backups older than (days): ")
                confirm = input(f"Remove old backups from {backup_dir}? (y/n): ")
                if confirm.lower() == "y":
                    subprocess.run(
                        [
                            "find",
                            backup_dir,
                            "-type",
                            "f",
                            "-mtime",
                            f"+{days}",
                            "-delete",
                        ]
                    )
                    print("Old backups cleaned successfully")

            elif choice == "4":
                backup_dir = input("Enter backup destination directory: ")
                source_dir = input("Enter directory to backup: ")
                backup_name = (
                    f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
                )

                print("\nCreating backup...")
                subprocess.run(
                    [
                        "sudo",
                        "tar",
                        "czf",
                        os.path.join(backup_dir, backup_name),
                        source_dir,
                    ]
                )
                print(f"Backup created: {backup_name}")

            elif choice == "0":
                break
            else:
                print("Invalid option. Please try again.")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def schedule_maintenance():
    try:
        print("\n--- Schedule Maintenance Tasks ---")

        while True:
            print("\nScheduling Options:")
            print("1. List scheduled tasks")
            print("2. Add maintenance task")
            print("3. Remove maintenance task")
            print("4. Enable/Disable task")
            print("0. Back")

            choice = input("Select option: ")

            if choice == "1":
                print("\nScheduled maintenance tasks:")
                cron = CronTab(user=True)
                for job in cron:
                    if job.comment.startswith("maintenance_"):
                        print(f"Task: {job.comment}")
                        print(f"Schedule: {job.slices}")
                        print(f"Command: {job.command}")
                        print(f"Enabled: {job.is_enabled()}")
                        print("-" * 50)

            elif choice == "2":
                print("\nMaintenance Task Types:")
                print("1. System cleanup")
                print("2. System updates")
                print("3. Backup")
                print("4. Custom task")

                task_type = input("Select task type: ")

                if task_type in ["1", "2", "3", "4"]:
                    schedule = input(
                        "Enter cron schedule (e.g., 0 0 * * * for daily at midnight): "
                    )

                    cron = CronTab(user=True)
                    if task_type == "1":
                        cmd = f"{sys.executable} {__file__} --cleanup"
                        comment = "maintenance_cleanup"
                    elif task_type == "2":
                        cmd = "sudo apt update && sudo apt upgrade -y"
                        comment = "maintenance_updates"
                    elif task_type == "3":
                        backup_dir = input("Enter backup directory: ")
                        source_dir = input("Enter directory to backup: ")
                        cmd = f"tar czf {backup_dir}/backup_$(date +%Y%m%d).tar.gz {source_dir}"
                        comment = "maintenance_backup"
                    else:
                        cmd = input("Enter custom command: ")
                        comment = "maintenance_custom"

                    job = cron.new(command=cmd, comment=comment)
                    job.setall(schedule)

                    if job.is_valid():
                        cron.write()
                        print("Maintenance task scheduled successfully")
                    else:
                        print("Invalid cron schedule")

            elif choice == "3":
                cron = CronTab(user=True)
                maintenance_jobs = [
                    (i, job)
                    for i, job in enumerate(cron)
                    if job.comment.startswith("maintenance_")
                ]

                if maintenance_jobs:
                    print("\nMaintenance Tasks:")
                    for i, job in maintenance_jobs:
                        print(f"{i}. {job.comment}: {job.command}")

                    job_index = input("Enter task number to remove: ")
                    try:
                        job_index = int(job_index)
                        if 0 <= job_index < len(maintenance_jobs):
                            cron.remove(maintenance_jobs[job_index][1])
                            cron.write()
                            print("Task removed successfully")
                        else:
                            print("Invalid task number")
                    except ValueError:
                        print("Invalid input")
                else:
                    print("No maintenance tasks found")

            elif choice == "4":
                cron = CronTab(user=True)
                maintenance_jobs = [
                    (i, job)
                    for i, job in enumerate(cron)
                    if job.comment.startswith("maintenance_")
                ]

                if maintenance_jobs:
                    print("\nMaintenance Tasks:")
                    for i, job in maintenance_jobs:
                        print(f"{i}. {job.comment}: Enabled={job.is_enabled()}")

                    job_index = input("Enter task number to toggle: ")
                    try:
                        job_index = int(job_index)
                        if 0 <= job_index < len(maintenance_jobs):
                            job = maintenance_jobs[job_index][1]
                            job.enable(not job.is_enabled())
                            cron.write()
                            print("Task status toggled successfully")
                        else:
                            print("Invalid task number")
                    except ValueError:
                        print("Invalid input")
                else:
                    print("No maintenance tasks found")

            elif choice == "0":
                break

    except Exception as e:
        print(f"An error occurred: {e}")


# --- Helper Functions for System Maintenance ---
def get_disk_usage_info():
    """Get detailed disk usage information"""
    disk_info = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disk_info.append(
                {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                }
            )
        except Exception:
            continue
    return disk_info


def get_memory_info():
    """Get detailed memory usage information"""
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "memory": {
            "total": memory.total,
            "used": memory.used,
            "free": memory.free,
            "percent": memory.percent,
            "cached": memory.cached,
            "buffers": memory.buffers,
        },
        "swap": {
            "total": swap.total,
            "used": swap.used,
            "free": swap.free,
            "percent": swap.percent,
        },
    }


def get_service_status():
    """Get status of important system services"""
    services = ["ssh", "apache2", "mysql", "postgresql", "nginx"]
    status = {}
    for service in services:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service], capture_output=True, text=True
            )
            status[service] = result.stdout.strip()
        except subprocess.CalledProcessError:
            status[service] = "unknown"
    return status


def generate_system_report(output_file="system_report.txt"):
    """Generate a comprehensive system report"""
    try:
        with open(output_file, "w") as f:
            # System Information
            uname = platform.uname()
            f.write("=== System Information ===\n")
            f.write(f"System: {uname.system}\n")
            f.write(f"Node Name: {uname.node}\n")
            f.write(f"Release: {uname.release}\n")
            f.write(f"Version: {uname.version}\n")
            f.write(f"Machine: {uname.machine}\n")
            f.write(f"Processor: {uname.processor}\n\n")

            # Disk Usage
            f.write("=== Disk Usage ===\n")
            disk_info = get_disk_usage_info()
            for disk in disk_info:
                f.write(f"Device: {disk['device']}\n")
                f.write(f"Mountpoint: {disk['mountpoint']}\n")
                f.write(f"Usage: {disk['percent']}%\n\n")

            # Memory Usage
            f.write("=== Memory Usage ===\n")
            memory_info = get_memory_info()
            f.write(f"Memory: {memory_info['memory']['percent']}% used\n")
            f.write(f"Swap: {memory_info['swap']['percent']}% used\n\n")

            # Service Status
            f.write("=== Service Status ===\n")
            service_status = get_service_status()
            for service, status in service_status.items():
                f.write(f"{service}: {status}\n")

            # Last System Updates
            f.write("\n=== Last System Updates ===\n")
            with open("/var/log/apt/history.log") as apt_log:
                f.write(apt_log.read())

            print(f"System report generated: {output_file}")

    except Exception as e:
        print(f"Error generating system report: {e}")


def check_system_security():
    """Perform basic security checks"""
    security_issues = []

    # Check SSH configuration
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            ssh_config = f.read()
            if "PermitRootLogin yes" in ssh_config:
                security_issues.append("SSH root login is enabled")
            if "PasswordAuthentication yes" in ssh_config:
                security_issues.append("SSH password authentication is enabled")
    except Exception:
        security_issues.append("Could not check SSH configuration")

    # Check for unattended upgrades
    try:
        if not os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
            security_issues.append("Unattended upgrades not configured")
    except Exception:
        security_issues.append("Could not check unattended upgrades")

    # Check firewall status
    try:
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        if "Status: inactive" in result.stdout:
            security_issues.append("Firewall is inactive")
    except Exception:
        security_issues.append("Could not check firewall status")

    return security_issues


# --- Hardware Management Functions ---
def hardware_management():
    while True:
        print("\n--- Hardware Management ---")
        print("1. List Hardware Information")
        print("2. Monitor Hardware Status")
        print("3. Configure Hardware")
        print("4. Hardware Diagnostics")
        print("5. Power Management")
        print("6. Driver Management")
        print("7. Hardware Alerts")
        print("0. Back to Main Menu")

        choice = input("Select an option: ")

        if choice == "1":
            list_hardware_info()
        elif choice == "2":
            monitor_hardware()
        elif choice == "3":
            configure_hardware()
        elif choice == "4":
            hardware_diagnostics()
        elif choice == "5":
            power_management()
        elif choice == "6":
            driver_management()
        elif choice == "7":
            hardware_alerts()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def list_hardware_info():
    try:
        print("\n=== Hardware Information ===")

        # CPU Information
        print("\n--- CPU Information ---")
        subprocess.run(["lscpu"])

        # Memory Information
        print("\n--- Memory Information ---")
        subprocess.run(["free", "-h"])

        # Disk Information
        print("\n--- Disk Information ---")
        subprocess.run(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"])

        # PCI Devices
        print("\n--- PCI Devices ---")
        subprocess.run(["lspci"])

        # USB Devices
        print("\n--- USB Devices ---")
        subprocess.run(["lsusb"])

        # Network Interfaces
        print("\n--- Network Interfaces ---")
        subprocess.run(["ip", "link", "show"])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def monitor_hardware():
    try:
        print("Monitoring hardware (Press Ctrl+C to stop)...")
        while True:
            os.system("clear")

            # CPU Temperature
            print("=== CPU Temperature ===")
            try:
                subprocess.run(["sensors"])
            except subprocess.CalledProcessError:
                print("Temperature sensors not available")

            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            print("\n=== CPU Usage ===")
            for i, percent in enumerate(cpu_percent):
                print(f"Core {i}: {percent}%")

            # Memory Usage
            memory = psutil.virtual_memory()
            print("\n=== Memory Usage ===")
            print(f"Total: {memory.total / (1024**3):.2f} GB")
            print(f"Used: {memory.used / (1024**3):.2f} GB ({memory.percent}%)")

            # Disk I/O
            disk_io = psutil.disk_io_counters()
            print("\n=== Disk I/O ===")
            print(f"Read: {disk_io.read_bytes / (1024**3):.2f} GB")
            print(f"Written: {disk_io.write_bytes / (1024**3):.2f} GB")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"An error occurred: {e}")


def configure_hardware():
    while True:
        print("\n--- Hardware Configuration ---")
        print("1. Configure Display")
        print("2. Configure Audio")
        print("3. Configure Network Interfaces")
        print("4. Configure Power Management")
        print("5. Configure Input Devices")
        print("0. Back")

        choice = input("Select option: ")

        try:
            if choice == "1":
                subprocess.run(["xrandr"])
                display = input("Enter display to configure: ")
                resolution = input("Enter resolution (e.g., 1920x1080): ")
                subprocess.run(["xrandr", "--output", display, "--mode", resolution])

            elif choice == "2":
                subprocess.run(["alsamixer"])

            elif choice == "3":
                subprocess.run(["nmtui"])

            elif choice == "4":
                subprocess.run(["sudo", "powertop"])

            elif choice == "5":
                subprocess.run(["sudo", "nano", "/etc/X11/xorg.conf.d/"])

            elif choice == "0":
                break

        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")


def hardware_diagnostics():
    try:
        print("\n=== Hardware Diagnostics ===")

        # Memory test
        print("\n1. Testing memory...")
        subprocess.run(["sudo", "memtester", "1M", "1"])

        # Disk test
        print("\n2. Testing disk...")
        disk = input("Enter disk to test (e.g., /dev/sda): ")
        subprocess.run(["sudo", "badblocks", "-v", disk])

        # CPU stress test
        print("\n3. CPU stress test (60 seconds)...")
        subprocess.run(["stress", "--cpu", "8", "--timeout", "60s"])

        # SMART disk diagnostics
        print("\n4. SMART disk diagnostics...")
        subprocess.run(["sudo", "smartctl", "-H", disk])

        print("\nDiagnostics completed.")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def power_management():
    while True:
        print("\n--- Power Management ---")
        print("1. Show Power Status")
        print("2. Set Power Profile")
        print("3. Configure Sleep Settings")
        print("4. Battery Information")
        print("5. Power Usage Analysis")
        print("0. Back")

        choice = input("Select option: ")

        try:
            if choice == "1":
                subprocess.run(
                    ["upower", "-i", "/org/freedesktop/UPower/devices/battery_BAT0"]
                )

            elif choice == "2":
                print("\nAvailable profiles:")
                print("1. Performance")
                print("2. Balanced")
                print("3. Power Saver")
                profile = input("Select profile: ")
                if profile == "1":
                    subprocess.run(
                        ["sudo", "cpupower", "frequency-set", "-g", "performance"]
                    )
                elif profile == "2":
                    subprocess.run(
                        ["sudo", "cpupower", "frequency-set", "-g", "ondemand"]
                    )
                elif profile == "3":
                    subprocess.run(
                        ["sudo", "cpupower", "frequency-set", "-g", "powersave"]
                    )

            elif choice == "3":
                subprocess.run(["sudo", "systemctl", "status", "sleep.target"])

            elif choice == "4":
                subprocess.run(["acpi", "-V"])

            elif choice == "5":
                subprocess.run(["powertop"])

            elif choice == "0":
                break

        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")


def driver_management():
    while True:
        print("\n--- Driver Management ---")
        print("1. List Loaded Drivers")
        print("2. Check Driver Status")
        print("3. Update Drivers")
        print("4. Install New Driver")
        print("5. Remove Driver")
        print("0. Back")

        choice = input("Select option: ")

        try:
            if choice == "1":
                subprocess.run(["lsmod"])

            elif choice == "2":
                driver = input("Enter driver name: ")
                subprocess.run(["modinfo", driver])

            elif choice == "3":
                print("Checking for driver updates...")
                subprocess.run(["sudo", "ubuntu-drivers", "autoinstall"])

            elif choice == "4":
                driver = input("Enter driver package name: ")
                subprocess.run(["sudo", "apt", "install", driver])

            elif choice == "5":
                driver = input("Enter driver name to remove: ")
                subprocess.run(["sudo", "modprobe", "-r", driver])

            elif choice == "0":
                break

        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")


def hardware_alerts():
    try:
        print("\nConfiguring hardware alerts...")

        # Temperature alerts
        max_temp = input("Enter maximum CPU temperature alert threshold (°C): ")

        # Disk space alerts
        disk_threshold = input("Enter disk space alert threshold (%): ")

        # Memory alerts
        mem_threshold = input("Enter memory usage alert threshold (%): ")

        print("\nMonitoring hardware (Press Ctrl+C to stop)...")
        while True:
            # Check CPU temperature
            temps = psutil.sensors_temperatures()
            for name, entries in temps.items():
                for entry in entries:
                    if entry.current > float(max_temp):
                        print(f"WARNING: {name} temperature is {entry.current}°C!")

            # Check disk space
            disk = psutil.disk_usage("/")
            if disk.percent > float(disk_threshold):
                print(f"WARNING: Disk usage is {disk.percent}%!")

            # Check memory
            memory = psutil.virtual_memory()
            if memory.percent > float(mem_threshold):
                print(f"WARNING: Memory usage is {memory.percent}%!")

            time.sleep(60)  # Check every minute

    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"An error occurred: {e}")


# --- Network Monitoring Functions ---
def network_monitoring():
    while True:
        print("\n--- Network Monitoring ---")
        print("1. Monitor Network Traffic")
        print("2. View Network Statistics")
        print("3. Monitor Connections")
        print("4. Packet Capture")
        print("5. Bandwidth Usage")
        print("6. Network Diagnostics")
        print("0. Back to Main Menu")

        choice = input("Select an option: ")

        if choice == "1":
            monitor_network_traffic()
        elif choice == "2":
            view_network_stats()
        elif choice == "3":
            monitor_connections()
        elif choice == "4":
            packet_capture()
        elif choice == "5":
            bandwidth_usage()
        elif choice == "6":
            network_diagnostics()
        elif choice == "0":
            break
        else:
            print("Invalid option. Please try again.")


def monitor_network_traffic():
    try:
        print("Monitoring network traffic (Press Ctrl+C to stop)...")

        # Get initial counters
        old_counters = psutil.net_io_counters()

        while True:
            time.sleep(1)
            new_counters = psutil.net_io_counters()

            # Calculate rates
            bytes_sent = new_counters.bytes_sent - old_counters.bytes_sent
            bytes_recv = new_counters.bytes_recv - old_counters.bytes_recv

            # Convert to MB/s
            mb_sent = bytes_sent / 1024 / 1024
            mb_recv = bytes_recv / 1024 / 1024

            # Update screen
            os.system("clear")
            print(f"Upload: {mb_sent:.2f} MB/s")
            print(f"Download: {mb_recv:.2f} MB/s")
            print("\nPacket Information:")
            print(f"Packets sent: {new_counters.packets_sent}")
            print(f"Packets received: {new_counters.packets_recv}")
            print(f"Errors in: {new_counters.errin}")
            print(f"Errors out: {new_counters.errout}")
            print(f"Drops in: {new_counters.dropin}")
            print(f"Drops out: {new_counters.dropout}")

            old_counters = new_counters

    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"An error occurred: {e}")


def view_network_stats():
    try:
        print("\n=== Network Statistics ===")

        # Interface statistics
        print("\nInterface Statistics:")
        subprocess.run(["netstat", "-i"])

        # Protocol statistics
        print("\nProtocol Statistics:")
        subprocess.run(["netstat", "-s"])

        # Routing table
        print("\nRouting Table:")
        subprocess.run(["netstat", "-r"])

        # Network interfaces
        print("\nNetwork Interfaces:")
        subprocess.run(["ip", "addr"])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def monitor_connections():
    try:
        print("Monitoring network connections (Press Ctrl+C to stop)...")
        while True:
            os.system("clear")

            # Get all connections
            connections = psutil.net_connections(kind="inet")

            # Count connections by status
            status_counts = {}
            for conn in connections:
                status = conn.status
                status_counts[status] = status_counts.get(status, 0) + 1

            print("=== Connection Status ===")
            for status, count in status_counts.items():
                print(f"{status}: {count}")

            print("\n=== Active Connections ===")
            print("Local Address\t\tRemote Address\t\tStatus\tPID")
            print("-" * 70)

            for conn in connections:
                if conn.status == "ESTABLISHED":
                    local = f"{conn.laddr.ip}:{conn.laddr.port}"
                    remote = (
                        f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    )
                    pid = conn.pid or "N/A"
                    print(f"{local:<20}\t{remote:<20}\t{conn.status}\t{pid}")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"An error occurred: {e}")


def packet_capture():
    try:
        print("\n=== Packet Capture ===")

        # List interfaces
        subprocess.run(["ip", "link", "show"])

        interface = input("\nEnter interface to capture (e.g., eth0): ")
        duration = input("Enter capture duration in seconds (default: 30): ") or "30"
        output_file = (
            input("Enter output file name (default: capture.pcap): ") or "capture.pcap"
        )

        print(f"\nCapturing packets on {interface} for {duration} seconds...")
        subprocess.run(
            ["sudo", "tcpdump", "-i", interface, "-w", output_file, "-G", duration]
        )

        print(f"\nCapture completed. File saved as {output_file}")

        # Analyze capture
        analyze = input("Would you like to analyze the capture? (y/n): ")
        if analyze.lower() == "y":
            subprocess.run(["tcpdump", "-r", output_file, "-n"])

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")


def bandwidth_usage():
    try:
        print("\n=== Bandwidth Usage Analysis ===")

        # Get all network interfaces
        interfaces = psutil.net_if_stats()

        print("\nAvailable interfaces:")
        for iface in interfaces:
            print(f"- {iface}")

        interface = input("\nEnter interface to monitor (or 'all'): ")
        duration = int(input("Enter monitoring duration in seconds: "))

        print(f"\nMonitoring bandwidth usage for {duration} seconds...")
        start_time = time.time()
        initial_counters = psutil.net_io_counters(pernic=True)

        try:
            while time.time() - start_time < duration:
                os.system("clear")
                current_counters = psutil.net_io_counters(pernic=True)

                # Calculate bandwidth for each interface
                for iface_name, current in current_counters.items():
                    if interface != "all" and iface_name != interface:
                        continue

                    initial = initial_counters[iface_name]
                    bytes_sent = current.bytes_sent - initial.bytes_sent
                    bytes_recv = current.bytes_recv - initial.bytes_recv

                    time_elapsed = time.time() - start_time

                    # Calculate rates in MB/s
                    upload_rate = bytes_sent / time_elapsed / (1024 * 1024)
                    download_rate = bytes_recv / time_elapsed / (1024 * 1024)

                    print(f"\nInterface: {iface_name}")
                    print(f"Upload Rate: {upload_rate:.2f} MB/s")
                    print(f"Download Rate: {download_rate:.2f} MB/s")
                    print(f"Total Upload: {bytes_sent / (1024*1024):.2f} MB")
                    print(f"Total Download: {bytes_recv / (1024*1024):.2f} MB")

                time.sleep(1)

        except KeyboardInterrupt:
            print("\nMonitoring stopped")

        # Generate summary report
        print("\nGenerating bandwidth usage report...")
        report_file = (
            f"bandwidth_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        with open(report_file, "w") as f:
            f.write("=== Bandwidth Usage Report ===\n\n")
            final_counters = psutil.net_io_counters(pernic=True)

            for iface_name, final in final_counters.items():
                if interface != "all" and iface_name != interface:
                    continue

                initial = initial_counters[iface_name]
                bytes_sent = final.bytes_sent - initial.bytes_sent
                bytes_recv = final.bytes_recv - initial.bytes_recv

                f.write(f"Interface: {iface_name}\n")
                f.write(f"Total Upload: {bytes_sent / (1024*1024):.2f} MB\n")
                f.write(f"Total Download: {bytes_recv / (1024*1024):.2f} MB\n")
                f.write(
                    f"Average Upload Rate: {(bytes_sent/duration) / (1024*1024):.2f} MB/s\n"
                )
                f.write(
                    f"Average Download Rate: {(bytes_recv/duration) / (1024*1024):.2f} MB/s\n\n"
                )

        print(f"Report saved to {report_file}")

    except Exception as e:
        print(f"An error occurred: {e}")


def network_diagnostics():
    try:
        print("\n=== Network Diagnostics ===")

        # DNS Resolution Test
        print("\n1. Testing DNS Resolution...")
        try:
            subprocess.run(["nslookup", "google.com"], check=True)
            print("DNS resolution: OK")
        except subprocess.CalledProcessError:
            print("DNS resolution: FAILED")

        # Ping Test
        print("\n2. Testing Network Connectivity...")
        try:
            subprocess.run(["ping", "-c", "4", "8.8.8.8"], check=True)
            print("Network connectivity: OK")
        except subprocess.CalledProcessError:
            print("Network connectivity: FAILED")

        # MTU Test
        print("\n3. Testing MTU Size...")
        interface = input("Enter interface name (e.g., eth0): ")
        try:
            subprocess.run(
                [
                    "ping",
                    "-c",
                    "3",
                    "-M",
                    "do",
                    "-s",
                    "1472",
                    "8.8.8.8",
                    "-I",
                    interface,
                ],
                check=True,
            )
            print("MTU size: OK")
        except subprocess.CalledProcessError:
            print("MTU size: Possible issues detected")

        # Port Scanning
        print("\n4. Testing Common Ports...")
        target = input("Enter host to test (default: localhost): ") or "localhost"
        common_ports = [21, 22, 80, 443, 3306, 5432]

        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"Port {port}: Open")
            else:
                print(f"Port {port}: Closed")
            sock.close()

        # Network Interface Status
        print("\n5. Checking Network Interfaces...")
        subprocess.run(["ip", "addr", "show"])

        # Routing Table
        print("\n6. Checking Routing Table...")
        subprocess.run(["route", "-n"])

        # Network Load
        print("\n7. Checking Network Load...")
        subprocess.run(["netstat", "-i"])

        # Generate Report
        print("\nGenerating diagnostic report...")
        report_file = f"network_diagnostics_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with open(report_file, "w") as f:
            f.write("=== Network Diagnostic Report ===\n\n")

            # System Information
            f.write("System Information:\n")
            uname = platform.uname()
            f.write(f"OS: {uname.system} {uname.release}\n")
            f.write(f"Hostname: {uname.node}\n\n")

            # Network Interfaces
            f.write("Network Interfaces:\n")
            interfaces = psutil.net_if_addrs()
            for interface_name, addresses in interfaces.items():
                f.write(f"\n{interface_name}:\n")
                for addr in addresses:
                    f.write(f"  {addr.family.name}: {addr.address}\n")

            # Network Statistics
            f.write("\nNetwork Statistics:\n")
            net_io = psutil.net_io_counters()
            f.write(f"Bytes Sent: {net_io.bytes_sent}\n")
            f.write(f"Bytes Received: {net_io.bytes_recv}\n")
            f.write(f"Packets Sent: {net_io.packets_sent}\n")
            f.write(f"Packets Received: {net_io.packets_recv}\n")

        print(f"Report saved to {report_file}")

    except Exception as e:
        print(f"An error occurred: {e}")


# --- Main Program Execution ---
def initialize_environment():
    """Initialize the program environment and check dependencies"""
    try:
        # Create necessary directories
        directories = [
            "/var/log/sysadmin_tool",
            "/etc/sysadmin_tool",
            "/var/backups/sysadmin_tool",
        ]

        for directory in directories:
            os.makedirs(directory, exist_ok=True)

        # Check for required commands
        required_commands = ["apt", "systemctl", "netstat", "ip", "tcpdump", "ping"]

        missing_commands = []
        for cmd in required_commands:
            if not shutil.which(cmd):
                missing_commands.append(cmd)

        if missing_commands:
            print("Missing required commands:", ", ".join(missing_commands))
            print("Please install the necessary packages.")
            return False

        # Initialize logging
        logging.basicConfig(
            filename="/var/log/sysadmin_tool/sysadmin.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

        # Check for root privileges
        if os.geteuid() != 0:
            print("Warning: Some features require root privileges")
            print("Consider running the script with sudo")

        return True

    except Exception as e:
        print(f"Initialization error: {e}")
        return False


def cleanup_environment():
    """Cleanup actions before program exit"""
    try:
        # Clean up temporary files
        temp_files = glob.glob("/tmp/sysadmin_*")
        for file in temp_files:
            try:
                os.remove(file)
            except OSError:
                continue

        # Rotate log files if needed
        log_file = "/var/log/sysadmin_tool/sysadmin.log"
        if (
            os.path.exists(log_file) and os.path.getsize(log_file) > 10 * 1024 * 1024
        ):  # 10MB
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            shutil.move(log_file, f"{log_file}.{timestamp}")

        logging.info("Program terminated normally")

    except Exception as e:
        print(f"Cleanup error: {e}")


def handle_error(error, context=""):
    """Handle and log errors"""
    error_msg = f"{context}: {str(error)}" if context else str(error)
    logging.error(error_msg)
    print(f"Error: {error_msg}")

    if isinstance(error, subprocess.CalledProcessError):
        print(f"Command failed with return code {error.returncode}: {error.cmd}")
    elif isinstance(error, IOError):
        print(f"IOError: {error.filename} - {error.strerror}")
    elif isinstance(error, Exception):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"/var/log/sysadmin_tool/error_report_{timestamp}.txt"

        try:
            with open(report_file, "w") as f:
                f.write(f"Error Report - {datetime.datetime.now()}\n\n")
                f.write(f"Error Type: {type(error).__name__}\n")
                f.write(f"Error Message: {str(error)}\n")
                f.write(f"Context: {context}\n\n")
                f.write("Traceback:\n")
                import traceback

                traceback.print_exc(file=f)

            print(f"Error report generated: {report_file}")

        except Exception as e:
            print(f"Failed to create error report: {e}")


def main():
    """Main program execution"""
    if not initialize_environment():
        print("Failed to initialize program environment")
        sys.exit(1)

    try:
        while True:
            print("\n=== Linux System Administration Tool ===")
            print("1. User Management")
            print("2. Service Management")
            print("3. Network Management")
            print("4. System Monitoring")
            print("5. Process Management")
            print("6. Package Management")
            print("7. Log Management")
            print("8. System Maintenance")
            print("9. Hardware Management")
            print("10. Security Management")
            print("11. Backup Management")
            print("12. Network Monitoring")
            print("13. System Information")
            print("14. Scheduled Tasks")
            print("15. Documentation")
            print("0. Exit")

            choice = input("\nSelect an option: ")

            try:
                if choice == "1":
                    user_management()
                elif choice == "2":
                    service_management()
                elif choice == "3":
                    network_management()
                elif choice == "4":
                    system_monitoring()
                elif choice == "5":
                    process_management()
                elif choice == "6":
                    package_management()
                elif choice == "7":
                    log_management()
                elif choice == "8":
                    system_maintenance()
                elif choice == "9":
                    hardware_management()
                elif choice == "10":
                    security_management()
                elif choice == "11":
                    backup_management()
                elif choice == "12":
                    network_monitoring()
                elif choice == "13":
                    system_information()
                elif choice == "14":
                    scheduled_tasks()
                elif choice == "15":
                    display_readme()
                elif choice == "0":
                    break
                else:
                    print("Invalid option. Please try again.")

            except Exception as e:
                handle_error(e, f"Error in option {choice}")

    except KeyboardInterrupt:
        print("\nProgram terminated by user")
    except Exception as e:
        handle_error(e, "Critical error in main loop")
    finally:
        cleanup_environment()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--version":
            print("Linux System Administration Tool v1.0.0")
            sys.exit(0)
        elif sys.argv[1] == "--help":
            display_readme()
            sys.exit(0)

    main()
