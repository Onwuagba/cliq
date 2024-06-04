import re
from urllib.parse import urlparse
from PIL import Image
from shorty.models import Blacklist


def is_ip_blacklisted(ip_address):
    """
    Check if the given IP address is blacklisted.

    Parameters:
        ip_address (str): The IP address to check.

    Returns:
        bool: True if the IP address is blacklisted, False otherwise.
    """
    return Blacklist.objects.filter(entry=ip_address, blacklist_type="ip").exists()


def contains_blacklisted_texts(url):
    """
    Check if the given URL contains any blacklisted texts.

    Parameters:
        url (str): The URL to check.

    Returns:
        bool: True if the URL contains any blacklisted texts, False otherwise.
    """
    blacklisted_texts = Blacklist.objects.filter(blacklist_type="text").values_list(
        "entry", flat=True
    )
    parsed_url = urlparse(url)
    url_components = [
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        parsed_url.query,
        parsed_url.fragment,
    ]
    for component in url_components:
        if any(blacklisted_text in component for blacklisted_text in blacklisted_texts):
            return True
    return False


def is_domain_blacklisted(url):
    """
    Check if the given URL is blacklisted by domain name.

    Parameters:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is blacklisted by domain name, False otherwise.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(":")[0]  # Remove port if present
    if domain.startswith("www."):
        domain = domain[4:]
    return Blacklist.objects.filter(entry=domain, blacklist_type="domain").exists()


def get_user_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def is_valid_time_24h_format(time_str):
    """
    Check if the given time string is in a valid 24-hour format (HH:MM).

    Parameters:
    time_str (str): The time string to validate.

    Returns:
    bool: True if the time string is valid, False otherwise.
    """
    pattern = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9])?$")
    match = pattern.match(str(time_str))

    # Return True if it's a valid time, False otherwise
    return bool(match)


def is_valid_image(
    file_path,
    valid_formats=["JPEG", "PNG", "JPG", "WEBP"],
    min_width=100,
    min_height=100,
):
    """
    Check if the given file is a valid image.

    Parameters:
    file_path (str): The path to the image file.
    valid_formats (list, optional): List of valid image formats (e.g., ["JPEG", "PNG"]).
    min_width (int, optional): Minimum width of the image.
    min_height (int, optional): Minimum height of the image.

    Returns:
    bool: True if the image is valid, False otherwise.
    """
    try:
        with Image.open(file_path) as img:
            # Verify the image to check for corruption
            img.verify()

            # Re-open the image file to get format and size info
            img = Image.open(file_path)

            # Check image format
            if valid_formats and img.format not in valid_formats:
                return False, "Invalid image format. Accepted formats: {}".format(
                    valid_formats
                )

            # Check image dimensions
            width, height = img.size
            if (min_width and width < min_width) or (
                min_height and height < min_height
            ):
                return False, "Adjust image dimension to {}x{}".format(
                    min_width, min_height
                )

            return True, "_"
    except Exception as e:
        print(str(e.args[0]), file_path)
        return False, "Error validating image"


def validate_link(value):
    parsed_url = urlparse(value)
    if not parsed_url.scheme:
        value = f"http://{value}"
    return value
