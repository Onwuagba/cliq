from rest_framework.exceptions import ValidationError


def check_email_username(data):
    """
    Checks if the input dictionary contains either "username" or "email" keys,
    and raises a ValidationError if it doesn't.

    Args:
    - data (dict): A dictionary that is checked for "username" or "email" keys.

    Raises:
    - ValidationError: If "username" or "email" keys are not found in the dictionary.

    Returns:
    - None
    """
    if not {"username", "email"}.intersection(map(str.lower, data.keys())):
        raise ValidationError("Email or Username is required")
