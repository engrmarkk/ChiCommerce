import random
import re


# Generate OTP for password reset
def generate_otp():
    return str(random.randint(1000, 9999))


def validate_password(password):
    # Check password length
    if len(password) < 6:
        return "Password must be at least 6 characters long."

    # Check for at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."

    # Check for at least one number
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."

    # Check for at least one special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."

    # If all checks pass
    return None


def is_valid_email(email):
    regex = re.compile(
        r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
    )
    if re.fullmatch(regex, email):
        return email.lower()
    return False


def validate_phone_number(phone_number):
    if not len(phone_number) == 11:
        return "Phone number must be 11 digits"
    if not phone_number.startswith("0"):
        return "Phone number must start with 0"
    if not phone_number[1:].isdigit():
        return "Phone number must contain only digits"
    return None
