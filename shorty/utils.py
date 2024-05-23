from urllib.parse import urlparse
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
