import os

from dotenv import load_dotenv

load_dotenv()

email_sender = os.getenv("EMAIL_SENDER")
admin_support_sender = os.getenv("SUPPORT_EMAIL")

CHANNELS = (
    ("facebook", "facebook"),
    ("twitter", "twitter"),
    ("google", "google"),
    ("email", "email"),
)

BLACKLIST = (
    ("ip", "ip"),
    ("domain", "domain"),
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
