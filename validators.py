import re
from email_validator import validate_email, EmailNotValidError

def is_valid_email(email):
    """Validate email format"""
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def sanitize_input(text, max_length=1000):
    """Sanitize user input"""
    if not text:
        return ""
    # Remove null bytes
    text = text.replace('\x00', '')
    # Limit length
    return text[:max_length]

def is_strong_password(password):
    """Check if password is strong enough"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"
