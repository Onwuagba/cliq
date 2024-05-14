import contextlib
import datetime
import ipaddress
import uuid
import secrets
import string

from django.contrib.auth.models import (
    AbstractUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models, IntegrityError, transaction
from django.db.models.query import QuerySet
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.contrib.auth.hashers import make_password
from rest_framework.authtoken.models import Token

from main.constants import BLACKLIST, CHANNELS, OS_CHOICES, REDIRECT_CHOICES, STATUS
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


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(
        _("Deactivate Account"),
        default=False,
        help_text=_("Designates whether this entry has been deleted."),
    )

    class Meta:
        abstract = True
        ordering = ["-created_at", "-updated_at"]


class CustomAdminManager(BaseUserManager):
    """relevant for admin to still see soft-deleted users
    that is hidden via the UserManager class."""

    pass


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")

        user = self.model(
            email=self.normalize_email(email),
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if password is None:
            raise TypeError("Superusers must have a password.")

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, password, **extra_fields)

    def get_queryset(self) -> QuerySet:
        queryset = super().get_queryset()

        # Check if the user is a superuser
        User = get_user_model()
        if (
            hasattr(User, "is_superuser")
            and User.is_authenticated
            and User.is_superuser
        ):
            return queryset

        # Filter out soft-deleted users
        if hasattr(self.model, "is_deleted"):
            return queryset.filter(is_deleted=False, is_active=True)
        else:
            return queryset.filter(is_active=True)


class UserAccount(AbstractUser, PermissionsMixin, BaseModel):
    id = models.UUIDField(
        default=uuid.uuid4, editable=False, unique=True, primary_key=True
    )
    first_name = models.CharField(
        max_length=50, validators=[validate_name], null=False, blank=False
    )
    last_name = models.CharField(
        max_length=50, validators=[validate_name], null=False, blank=False
    )
    email = models.EmailField(db_index=True, max_length=255, unique=True)
    is_active = models.BooleanField(
        _("Activate Account"),
        default=False,
        help_text=_(
            "Designates whether the user has completed validation and is active."
        ),
    )
    channel = models.CharField(
        _("Channel"),
        choices=CHANNELS,
        max_length=30,
        default="email",
        help_text=_("Select channel from which the user was created."),
    )

    REQUIRED_FIELDS = ["first_name", "last_name"]
    USERNAME_FIELD = "email"

    objects = UserManager()
    admin_objects = CustomAdminManager()  # manager for admin

    def __str__(self):
        return self.first_name


class CustomToken(Token):
    id = models.UUIDField(_("ID"), default=uuid.uuid4, editable=False, unique=True)
    expiry_date = models.DateTimeField(null=False, blank=False)
    verified_on = models.DateTimeField(null=True, blank=True)

    def create_expiry_date(self, created: datetime.datetime) -> datetime.datetime:
        """
        Creates an expiry date for the token.

        Args:
            created (datetime.datetime): The creation date of the token.

        Returns:
            datetime.datetime: The expiry date of the token.
        """
        return created + datetime.timedelta(days=3) if created else None

    def save(self, *args, **kwargs):
        if self._state.adding:
            while True:
                with contextlib.suppress(IntegrityError):
                    with transaction.atomic():
                        if not self.created:
                            self.created = timezone.localtime()
                        if not self.key:
                            self.key = self.generate_key()
                        self.expiry_date = self.create_expiry_date(self.created)
                        super(Token, self).save(*args, **kwargs)
                        break  # Exit the loop if the expiry is set successfully
        else:
            super(Token, self).save(*args, **kwargs)

