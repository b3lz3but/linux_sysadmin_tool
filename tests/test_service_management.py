
import sys
import os
import pytest

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from service_management import manage_service

# Mock subprocess to avoid real system changes
def mock_subprocess_run(*args, **kwargs):
    return None

def test_manage_service(monkeypatch):
    monkeypatch.setattr("subprocess.run", mock_subprocess_run)
    assert manage_service("start", "testservice") is None
