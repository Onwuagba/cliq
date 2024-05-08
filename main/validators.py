import re

from django.core.exceptions import ValidationError


def validate_name(value):
    """
    Validates the input value for a name using a specific pattern.

    Parameters:
    value (str): The input value to be validated.

    Raises:
    ValidationError: If the input value does not match the specified pattern.
    """
    # This pattern allows letters, spaces, hyphens, and apostrophes.
    pattern = r"^[A-Za-z\d\s'-]+$"

    if not re.match(pattern, value):
        raise ValidationError("Enter a valid name.")