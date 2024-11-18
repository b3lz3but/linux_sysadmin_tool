
import pytest
from utils import sanitize_input

def test_sanitize_input_valid():
    assert sanitize_input("valid_input123") == "valid_input123"
    assert sanitize_input("another_valid-input_456") == "another_valid-input_456"

def test_sanitize_input_invalid():
    with pytest.raises(ValueError):
        sanitize_input("invalid input!@#")
