
# Centralized logging for the system
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("sysadmin_tool.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("SysAdminTool")
    