
import subprocess
import tempfile
from core import logger, load_config

config = load_config()

def format_and_mount_disk(device, filesystem=None, mount_point=None):
    filesystem = filesystem or config.get('default_filesystem', 'ext4')
    mount_point = mount_point or config.get('default_mount_point', '/mnt')
    
    try:
        subprocess.run(['sudo', 'mkfs', '-t', filesystem, device], check=True)
        subprocess.run(['sudo', 'mkdir', '-p', mount_point], check=True)
        subprocess.run(['sudo', 'mount', device, mount_point], check=True)

        uuid = subprocess.check_output(['sudo', 'blkid', '-s', 'UUID', '-o', 'value', device]).decode().strip()
        fstab_entry = f'UUID={uuid} {mount_point} {filesystem} defaults 0 2'

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            with open('/etc/fstab', 'r') as f:
                temp_file.write(f.read())
            temp_file.write(f'\n{fstab_entry}\n')

        subprocess.run(['sudo', 'mv', temp_file.name, '/etc/fstab'], check=True)
        logger.info(f"Device {device} formatted with {filesystem} and mounted at {mount_point}")
        print(f"Device {device} formatted with {filesystem} and mounted at {mount_point}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to format and mount {device}: {e}")
        print(f"An error occurred: {e}")
