
# Linux SysAdmin Tool

## Overview
The Linux SysAdmin Tool is a modular command-line application designed for simplifying system administration tasks on Linux. It includes functionalities like user management, service management, filesystem handling, network diagnostics, and security management.

## Project Structure
```
linux_sysadmin_tool/
├── core.py                  # Core utilities: logging, configuration, validation
├── user_management.py       # User management functionalities
├── service_management.py    # Service management functionalities
├── network_management.py    # Network diagnostics and interface management
├── filesystem_management.py # Filesystem formatting and mounting
├── system_monitoring.py     # Resource and performance monitoring
├── security_management.py   # Security updates and configurations
├── config.yaml              # Configuration file for default settings
├── main.py                  # Main entry point with dynamic menu
└── tests/                   # Directory containing pytest scripts
    ├── test_core.py
    ├── test_user_management.py
    ├── test_service_management.py
    └── test_filesystem_management.py
```

## Setup Instructions

### Prerequisites
- **Python 3.x**: Ensure Python 3 is installed.
- **Required Modules**: Install the following Python libraries:
  ```bash
  pip install pytest pyyaml
  ```
- **Root Privileges**: The tool requires `sudo` access for certain operations.

### Configuration
Edit the `config.yaml` file to specify default settings:
```yaml
default_filesystem: ext4
default_mount_point: /mnt
default_log_level: DEBUG
```

- **`default_filesystem`**: Filesystem type for disk operations.
- **`default_mount_point`**: Default directory for mounting disks.
- **`default_log_level`**: Logging verbosity.

### Running the Tool
1. **Navigate to the project directory**:
   ```bash
   cd linux_sysadmin_tool
   ```
2. **Launch the tool**:
   ```bash
   python3 main.py
   ```

## Features and Usage

### User Management
- **Add a User**: Creates a new system user.
- **Delete a User**: Removes a user and their home directory.
- **Reset Password**: Resets the password for a user.
- **Modify Group Membership**: Adds or removes a user from groups.
- **Lock/Unlock User Account**: Secures or enables access to an account.

### Service Management
- Start, stop, restart, enable, or disable services.
- Check the status of a service or list all running services.

### Network Management
- **Ping a Host**: Test connectivity to a network address.
- **Display Interfaces**: List all active network interfaces.
- **Test Port Connectivity**: Verify if a specific port is open.

### Filesystem Management
- **Format and Mount Disk**: Format a disk and mount it to a directory.
- **Check Disk Space**: Show disk usage statistics.
- **Resize Filesystem**: Adjust the size of a filesystem.

### System Monitoring
- Monitor CPU, memory, and disk usage.
- Display active processes and system load.

### Security Management
- Apply system security updates.
- Configure SSH settings.
- Manage Fail2Ban or rootkit scanning.

## Testing the Project

### Run Tests
Use `pytest` to validate the functionality:
```bash
pytest tests/
```

### Test Coverage
- **`test_core.py`**: Tests for configuration loading and input validation.
- **`test_user_management.py`**: Tests for adding and deleting users.
- **`test_service_management.py`**: Tests for managing system services.
- **`test_filesystem_management.py`**: Tests for disk formatting and mounting.

## Error Logs
Logs are saved to `sysadmin_tool.log` in the project directory. Adjust the logging level in `config.yaml` if needed.

## Extending the Tool
To add new features:
1. Create a new `.py` file in the project directory.
2. Define your functions and integrate them with the `main.py` menu.
3. Add a test file in the `tests/` directory to ensure reliability.
