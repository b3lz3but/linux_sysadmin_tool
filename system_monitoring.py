
import psutil
from core import logger

def display_resource_usage():
    try:
        print("\nCPU Usage:")
        cpu_usage = psutil.cpu_percent()
        print(f"CPU Usage: {cpu_usage}%")
        print("\nMemory Usage:")
        memory = psutil.virtual_memory()
        print(f"Total: {memory.total / (1024**3):.2f} GB")
        print(f"Used: {memory.used / (1024**3):.2f} GB")
        print(f"Free: {memory.free / (1024**3):.2f} GB")
        print(f"Memory Usage: {memory.percent}%")
        logger.info(f"System resource usage displayed. CPU: {cpu_usage}%, Memory: {memory.percent}%")
    except Exception as e:
        logger.error(f"Failed to display resource usage: {e}")
        print(f"An error occurred: {e}")
