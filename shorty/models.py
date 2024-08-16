import ipaddress
import os
import secrets
import string
from urllib.parse import urlencode
import uuid
import qrcode
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

from django.db import models, IntegrityError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator, MaxValueValidator, MinValueValidator
from django.contrib.auth.hashers import make_password, check_password

from main.constants import BLACKLIST, OS_CHOICES, REDIRECT_CHOICES, STATUS
from main.models import BaseModel, UserAccount


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

        # Filter out expired links
        queryset = queryset.filter(
            models.Q(expiration_date__isnull=True)
            | models.Q(expiration_date__gte=timezone.now())
        )

        # Remove deleted objects
        queryset = queryset.filter(is_deleted=False)

        # Prefetch related UserShortLink objects if available
        queryset = queryset.prefetch_related("link_shortlink")

        # Filter objects with link_review status "approved"
        queryset = queryset.exclude(
            id__in=[
                obj.id
                for obj in queryset
                if hasattr(obj, "link_review")
                and obj.link_review.status.lower() != "approved"
            ]
        )

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
    entry = models.CharField(
        max_length=30, unique=True, db_index=True)
    blacklist_type = models.CharField(
        max_length=30, choices=BLACKLIST)

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
        max_length=200, validators=[validate_url]
    )  # created custom unique validator. One link can have multiple utm tags which is 1-1 relationship
    shortcode = models.CharField(
        max_length=50, unique=True, blank=True, db_index=True)
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
        max_length=20, protocol="IPv4")

    custom_objects = ShortLinkManager()

    def clean(self):
        now = timezone.now()
        if self.start_date and self.expiration_date:
            if self.start_date >= self.expiration_date:
                raise ValidationError(
                    "Start date must be before the expiration date.")
        elif self.start_date and self.start_date <= now:
            raise ValidationError("Start date cannot be in the past.")
        elif self.expiration_date and self.expiration_date <= now:
            raise ValidationError(
                "Expiration date cannot be in the past.")
        super().clean()

    def get_tags(self):
        return [tag.strip() for tag in self.tags.split(",")] if self.tags else []

    def get_full_url(self):
        full_url = f"{self.original_link}"

        if hasattr(self, "link_utm"):
            link_utm_obj = self.link_utm
            utm_params = {
                "utm_source": link_utm_obj.utm_source,
                "utm_medium": link_utm_obj.utm_medium,
                "utm_campaign": link_utm_obj.utm_campaign,
                "utm_term": link_utm_obj.utm_term,
                "utm_content": link_utm_obj.utm_content,
            }
            utm_query_string = urlencode(
                {k: v for k, v in utm_params.items() if v})
            full_url = f"{full_url}?{utm_query_string}"

        return full_url

    def save(self, *args, **kwargs):
        self.full_clean()
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

    def has_qr_code(self):
        return hasattr(self, 'link_qrcode')

    def __str__(self):
        return self.shortcode


class UserShortLink(BaseModel):
    # Model to store link info for authenticated users. Seperate from the link table cos the link table may also contain info for users not registered
    user = models.ForeignKey(
        UserAccount,
        on_delete=models.CASCADE,
        related_name="user_link",
        null=True,
        blank=True,
    )
    session_id = models.UUIDField(
        editable=False, null=True, blank=True
    )  # store session id for non authenticated users
    link = models.OneToOneField(
        ShortLink, on_delete=models.CASCADE, related_name="link_shortlink"
    )
    is_link_discoverable = models.BooleanField(default=False)
    is_link_masked = models.BooleanField(default=False)
    is_link_protected = models.BooleanField(default=False)
    link_password = models.CharField(
        max_length=200, null=True, blank=True)

    def __str__(self):
        return f"{(self.user or self.session_id)} - {self.link.shortcode}"

    def clean(self):
        super().clean()
        if self.is_link_protected and not self.link_password:
            raise ValidationError(
                "Password is required for protected links.")

    def save(self, *args, **kwargs):
        self.full_clean()
        if self.link_password:
            if not self.is_link_protected:
                self.is_link_protected = True

            # Check if the instance is being updated
            if self.pk is not None:
                # Fetch the current password from the database
                current_password = UserShortLink.objects.get(
                    pk=self.pk).link_password

                if not check_password(self.link_password, current_password):
                    self.link_password = make_password(
                        self.link_password)
            else:
                # Hash the password if this is a new instance
                self.link_password = make_password(self.link_password)

        if self._state.adding and not self.user and not self.session_id:
            self.session_id = uuid.uuid4()
        super().save(*args, **kwargs)


class LinkReview(BaseModel):
    # stores link info if user requests manual review of link that cannot be created due to blacklist entry
    link = models.OneToOneField(
        ShortLink, on_delete=models.CASCADE, related_name="link_review", db_index=True
    )
    status = models.CharField(
        choices=STATUS, max_length=10, default="pending", db_index=True
    )
    # needed for declined review
    reason = models.TextField(null=True, blank=True)

    # signal is triggered whenever status changes
    def __str__(self):
        return f"Review: {self.link.shortcode}"

    def save(self, *args, **kwargs):
        if self.status == "declined" and not self.reason:
            raise ValueError("Please add a reason for the review")

        super().save(*args, **kwargs)


class LinkCard(BaseModel):
    link = models.OneToOneField(
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
    # model to manage redirect rules specified by user. Could have different redirect rules based on certain configurations
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
    # one original link can have several utm tags but not all can be created at one
    # means that only one shortlink object can have multiple
    link = models.OneToOneField(
        ShortLink, on_delete=models.CASCADE, related_name="link_utm"
    )
    utm_source = models.CharField(
        max_length=100, null=True, blank=True)
    utm_medium = models.CharField(
        max_length=100, null=True, blank=True)
    utm_campaign = models.CharField(
        max_length=100, null=True, blank=True)
    utm_term = models.CharField(max_length=100, null=True, blank=True)
    utm_content = models.CharField(
        max_length=100, null=True, blank=True)

    def clean(self):
        super().clean()
        if not any(
            [
                self.utm_source,
                self.utm_medium,
                self.utm_campaign,
                self.utm_term,
                self.utm_content,
            ]
        ):
            raise ValidationError(
                "At least one UTM parameter is required.")

    def __str__(self):
        return f"UTM param: {self.link.shortcode}"


class ReportLink(BaseModel):
    # option for anyone to report a link we shortened.
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
    link = models.OneToOneField(
        ShortLink, on_delete=models.CASCADE, related_name="link_qrcode"
    )
    logo = models.ImageField(
        upload_to="uploads/qrcodes/logos/",
        null=True,
        blank=True,
        help_text="Image to be placed inside the QR code"
    )
    qr_title = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        default="Scan me",
        help_text="Text to be displayed beneath the QR code"
    )
    scan_count = models.PositiveIntegerField(default=0)
    box_size = models.PositiveIntegerField(
        default=10,
        validators=[MinValueValidator(1), MaxValueValidator(50)],
        help_text="Size of each box in the QR code"
    )
    border = models.PositiveIntegerField(
        default=4,
        validators=[MinValueValidator(0), MaxValueValidator(10)],
        help_text="Size of the border around the QR code"
    )
    fill_color = models.CharField(
        max_length=7,
        default="#000000",
        help_text="Color of the QR code (hex format)"
    )
    background_color = models.CharField(
        max_length=7,
        default="#FFFFFF",
        help_text="Background color of the QR code (hex format)"
    )

    def __str__(self):
        return f"QR Code: {self.link.shortcode}"

    def generate_qr_code(self):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=self.box_size,
            border=self.border,
        )
        qr.add_data(self.link.get_full_url())
        qr.make(fit=True)

        img = qr.make_image(fill_color=self.fill_color,
                            back_color=self.background_color).convert('RGBA')

        if self.logo:
            logo = Image.open(self.logo).convert('RGBA')
            logo_size = (img.size[0] // 4, img.size[1] // 4)
            logo = logo.resize(logo_size, Image.LANCZOS)

            # Create a white background for the logo
            logo_bg = Image.new('RGBA', logo.size,
                                (255, 255, 255, 255))
            logo_bg.paste(logo, (0, 0), logo)

            pos = ((img.size[0] - logo_size[0]) // 2,
                   (img.size[1] - logo_size[1]) // 2)
            img.paste(logo_bg, pos, logo_bg)

        if self.qr_title:
            # Load a larger font
            font_path = os.path.join(os.path.dirname(
                __file__), 'font', 'Roboto', 'Roboto-Bold.ttf')
            font_size = 30
            font = ImageFont.truetype(font_path, font_size)

            # Calculate the size needed for the title
            draw = ImageDraw.Draw(
                Image.new('RGBA', (1, 1), (0, 0, 0, 0)))
            _, _, text_width, text_height = draw.textbbox(
                (0, 0), text=self.qr_title, font=font)

            # Create a new image with extra space for the title
            new_height = img.height + text_height + 20  # 20 pixels padding
            img_with_title = Image.new('RGBA', (max(
                img.width, text_width + 20), new_height), self.background_color)
            img_with_title.paste(
                img, ((img_with_title.width - img.width) // 2, 0))

            # Draw the title
            draw = ImageDraw.Draw(img_with_title)
            text_position = (
                (img_with_title.width - text_width) // 2, img.height + 10)
            draw.text(text_position, self.qr_title.capitalize(),
                      font=font, fill=self.fill_color)

            img = img_with_title

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()


class Analytics(BaseModel):
    link = models.ForeignKey(
        ShortLink, on_delete=models.CASCADE, related_name="link_analytics"
    )
    ip_address = models.GenericIPAddressField(
        max_length=20, null=True, blank=True)
    os = models.CharField(
        max_length=30, choices=OS_CHOICES, null=True, blank=True)
    device_type = models.CharField(
        max_length=60, null=True, blank=True)
    click_time = models.TimeField(null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    language = models.CharField(max_length=50, null=True, blank=True)
    user_agent = models.CharField(
        max_length=255, null=True, blank=True)
    referrer = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        verbose_name_plural = "analytics"
