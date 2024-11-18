
import sys
import os
import pytest

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from filesystem_management import format_and_mount_disk

# Mock subprocess to avoid real system changes
def mock_subprocess_run(*args, **kwargs):
    return None

def mock_subprocess_check_output(*args, **kwargs):
    return b"mock-uuid"

def test_format_and_mount_disk(monkeypatch):
    monkeypatch.setattr("subprocess.run", mock_subprocess_run)
    monkeypatch.setattr("subprocess.check_output", mock_subprocess_check_output)
    assert format_and_mount_disk("/dev/sdb1") is None
