CHANNELS = (
    ("facebook", "facebook"),
    ("twitter", "twitter"),
    ("google", "google"),
    ("email", "email"),
)

BLACKLIST = (
    ("ip", "ip"),
    ("domain_name", "domain_name"),
    ("text", "text"),
)

STATUS = (
    ("pending", "pending"),
    ("approved", "approved"),
    ("declined", "declined"),
)

REDIRECT_CHOICES = [
    ("301", "301 Permanent Redirect"),
    ("302", "302 Temporary Redirect"),
]

OS_CHOICES = [
    ("windows", "windows"),
    ("android", "android"),
    ("iOS", "iOS"),
    ("apple", "apple"),
    ("linux", "linux"),
]
