
import sys
import os
import pytest

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from user_management import delete_user

# Mock subprocess to avoid real system changes
def mock_subprocess_run(*args, **kwargs):
    return None

def mock_input(prompt):
    return "y"

def test_delete_user(monkeypatch):
    monkeypatch.setattr("subprocess.run", mock_subprocess_run)
    monkeypatch.setattr("builtins.input", mock_input)
    assert delete_user("testuser") is None
