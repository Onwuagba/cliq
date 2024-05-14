import ipaddress
import secrets
import string

from django.db import models, IntegrityError
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.contrib.auth.hashers import make_password

from main.constants import BLACKLIST, OS_CHOICES, REDIRECT_CHOICES, STATUS
from main.models import BaseModel, UserAccount
from main.validators import validate_name


def generate_shortcode(length=6):
    """Generate a random string of specified length."""
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def validate_url(value):
    url_validator = URLValidator()

    try:
        # Check if the URL has a scheme
        if "://" not in value:
            value = f"http://{value}"

        url_validator(value)
    except ValidationError as e:
        raise ValidationError("Invalid URL") from e


class ShortLinkManager(models.Manager):
    def get_queryset(self):
        queryset = super().get_queryset()

        # Check if the user is a superuser
        User = get_user_model()
        if (
            hasattr(User, "is_superuser")
            and User.is_authenticated
            and User.is_superuser
        ):
            return queryset

        # Filter out expired links
        queryset = queryset.filter(
            models.Q(expiration_date__isnull=True)
            | models.Q(expiration_date__gte=timezone.now())
        )

        # Include UserShortLink objects if available
        if hasattr(self.model, "link_shortlink"):
            queryset = queryset.prefetch_related("link_shortlink")

        if hasattr(self.model, "link_review"):  # reverse related to LinkReview model
            qs = queryset.filter(link_review__status__iexact="approved")
            queryset = qs if qs else queryset

        # append utm tags to shortcode
        # if hasattr(self.model, "link_utm"):
        #     queryset = queryset.filter(link_utm__isnull=False)

        return queryset


class Category(BaseModel):
    name = models.CharField(max_length=30, unique=True)

    class Meta:
        verbose_name = "category"
        verbose_name_plural = "categories"

    def __str__(self):
        return self.name


class Blacklist(BaseModel):
    # model to hold blacklisted ip, domain names or texts (bet,porn,etc.) to prevent shortening of links
    entry = models.CharField(max_length=30, unique=True, db_index=True)
    blacklist_type = models.CharField(max_length=30, choices=BLACKLIST)

    def __str__(self):
        return self.entry

    def clean(self):
        super().clean()
        if self.blacklist_type == "ip":
            try:
                ipaddress.ip_address(self.entry)
            except ValueError:
                raise ValidationError("Invalid IP address format.")
        elif self.blacklist_type == "domain":
            validate_url(self.entry)


class ShortLink(BaseModel):
    original_link = models.URLField(
        max_length=200, unique=True, validators=[validate_url]
    )
    shortcode = models.CharField(max_length=50, unique=True, blank=True, db_index=True)
    category = models.ForeignKey(
        Category,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="link_category",
        db_index=True,
    )
    start_date = models.DateTimeField(
        help_text="Please use format: <em>YYYY-MM-DD</em>.", null=True, blank=True
    )  # if user wants to schedule when link should be active
    expiration_date = models.DateTimeField(
        help_text="Please use format: <em>YYYY-MM-DD</em>.",
        null=True,
        blank=True,
        db_index=True,
    )
    tags = models.CharField(
        max_length=100, null=True, blank=True, db_index=True
    )  # stores comma seperated tags
    ip_address = models.GenericIPAddressField(
        max_length=20, null=True, blank=True, protocol="IPv4"
    )

    objects = ShortLinkManager()

    def clean(self):
        if self.start_date and self.expiration_date:
            if self.start_date >= self.expiration_date:
                raise ValidationError("Start date must be before the expiration date.")
        elif self.start_date or self.expiration_date:
            now = timezone.now()
            if self.expiration_date <= now or self.start_date <= now:
                raise ValidationError("Start/Expiration date cannot be in the past.")
        super().clean()

    def get_tags(self):
        return self.tags.split(",") if self.tags else []

    def save(self, *args, **kwargs):
        if not self.shortcode:
            while True:
                self.shortcode = generate_shortcode()
                try:
                    super().save(*args, **kwargs)
                except IntegrityError:
                    # Shortcode already exists, regenerate and try again
                    continue
                except Exception as e:
                    print("Error saving link: %s" % e)
                    continue
                else:
                    # Unique shortcode generated, break the loop and exit
                    break
        else:
            super().save(*args, **kwargs)

    def __str__(self):
        return self.shortcode


class UserShortLink(BaseModel):
    # Model to store link info for authenticated users. Seperate from the link table cos the link table may also contain info for users not registered
    user = models.ForeignKey(
        UserAccount, on_delete=models.CASCADE, related_name="user_link"
    )
    link = models.OneToOneField(
        ShortLink, on_delete=models.CASCADE, related_name="link_shortlink"
    )
    is_link_discoverable = models.BooleanField(default=False)
    is_link_masked = models.BooleanField(default=False)
    is_link_protected = models.BooleanField(default=False)
    link_password = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.link.shortcode}"

    def clean(self):
        super().clean()
        if self.is_link_protected and not self.link_password:
            raise ValidationError("Password is required for protected links.")

    def save(self, *args, **kwargs):
        if self.link_password and not self.is_link_protected:
            self.is_link_protected = True
        if self._state.adding and self.link_password:
            self.link_password = make_password(self.link_password)
        super().save(*args, **kwargs)


class LinkReview(BaseModel):
    # stores link info if user requests manual review of link that cannot be created due to blacklist entry
    link = models.ForeignKey(
        ShortLink, on_delete=models.CASCADE, related_name="link_review", db_index=True
    )
    status = models.CharField(
        choices=STATUS, max_length=10, default="pending", db_index=True
    )
    ip_address = models.GenericIPAddressField(
        max_length=20, null=True, blank=True
    )  # ip of user making request

    # signal is triggered whenever status changes
    def __str__(self):
        return f"Review: {self.link.shortcode}"


class LinkCard(BaseModel):
    link = models.ForeignKey(
        ShortLink, on_delete=models.CASCADE, related_name="link_card"
    )
    card_title = models.CharField(max_length=60)
    card_description = models.CharField(max_length=155)
    card_thumbnail = models.ImageField(
        upload_to="uploads/card_thumbnails/", null=True, blank=True
    )  # update to use media server or CDN later

    def __str__(self):
        return f"Card: {self.link.shortcode}"


class LinkRedirect(BaseModel):
    link = models.ForeignKey(
        ShortLink, on_delete=models.CASCADE, related_name="link_redirect", db_index=True
    )
    redirect_link = models.URLField(
        max_length=200,
        validators=[validate_url],
    )
    device_type = models.CharField(
        max_length=30, choices=OS_CHOICES, null=True, blank=True
    )
    time_of_day = models.TimeField(
        null=True, blank=True
    )  # sample: HH:MM. read user time when writing to this
    country = models.CharField(max_length=50, null=True, blank=True)
    language = models.CharField(max_length=50, null=True, blank=True)
    redirect_rule = models.CharField(
        max_length=3, choices=REDIRECT_CHOICES, default="302"
    )

    def __str__(self):
        return f"Redirect: {self.link.shortcode}"


class LinkUTMParameter(BaseModel):
    link = models.ForeignKey(
        ShortLink, on_delete=models.CASCADE, related_name="link_utm"
    )
    utm_source = models.CharField(max_length=100, null=True, blank=True)
    utm_medium = models.CharField(max_length=100, null=True, blank=True)
    utm_campaign = models.CharField(max_length=100, null=True, blank=True)
    utm_term = models.CharField(max_length=100, null=True, blank=True)
    utm_content = models.CharField(max_length=100, null=True, blank=True)

    def save(self, *args, **kwargs):
        if not any(
            [
                self.utm_source,
                self.utm_medium,
                self.utm_campaign,
                self.utm_term,
                self.utm_content,
            ]
        ):
            raise ValidationError("At least one UTM parameter is required.")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"UTM param: {self.link.shortcode}"


class ReportLink(BaseModel):
    short_link = models.URLField(
        max_length=200,
        validators=[validate_url],
    )
    card_description = models.TextField()
    attachment = models.ImageField(
        upload_to="uploads/reported_links/", null=True, blank=True
    )  # move to CDN or media server later

    def __str__(self):
        return f"Reported Link: {self.short_link}"


class QRCode(BaseModel):
    # save info for generating QR and generate the QR code on the fly
    link = models.OneToOneField(
        ShortLink, on_delete=models.CASCADE, related_name="link_qrcode"
    )
    logo = models.ImageField(
        help_text="image to be placed inside the qr code",
        upload_to="uploads/qrcodes/",
        null=True,
        blank=True,
    )
    qr_title = models.CharField(
        help_text="Text to be displayed beneath the qr code",
        max_length=20,
        null=True,
        blank=True,
        default="scan me",
    )
    scan_count = models.IntegerField(default=0)

    def __str__(self):
        return f"QR Code: {self.link.shortcode}"


class Analytics(BaseModel):
    link = models.ForeignKey(
        ShortLink, on_delete=models.CASCADE, related_name="link_analytics"
    )
    ip_address = models.GenericIPAddressField(max_length=20, null=True, blank=True)
    os = models.CharField(max_length=30, choices=OS_CHOICES, null=True, blank=True)
    device_type = models.CharField(max_length=60, null=True, blank=True)
    click_time = models.TimeField(null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    language = models.CharField(max_length=50, null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    referrer = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        verbose_name_plural = "analytics"
