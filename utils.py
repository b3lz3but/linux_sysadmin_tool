
import re

def sanitize_input(user_input, allowed_chars=None):
    if allowed_chars is None:
        allowed_chars = r"a-zA-Z0-9_\-"
    pattern = re.compile(f"^[{allowed_chars}]+$")
    if not pattern.fullmatch(user_input):  # Use fullmatch for stricter validation
        raise ValueError(f"Input '{user_input}' contains invalid characters.")
    return user_input
