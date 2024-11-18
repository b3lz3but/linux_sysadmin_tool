
import pytest
from core import validate_username, validate_service_name

def test_validate_username():
    assert validate_username("validuser") == "validuser"
    with pytest.raises(ValueError):
        validate_username("invalid user")

def test_validate_service_name():
    assert validate_service_name("validservice") == "validservice"
    with pytest.raises(ValueError):
        validate_service_name("invalid service")
