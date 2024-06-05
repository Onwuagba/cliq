import datetime
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SL_SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("SL_DEBUG", False)

ALLOWED_HOSTS = ["*"] if DEBUG else os.getenv("SL_ALLOWED_HOSTS").split(",")


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "drf_yasg",
    "main",
    "common",
    "shorty",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "common.middleware.RestrictAdminMiddleware",
    "common.middleware.ChecksumMiddleware",
]

ROOT_URLCONF = "shortlink.urls"
APPEND_SLASH = True
AUTH_USER_MODEL = "main.UserAccount"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "shortlink.wsgi.application"


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("SL_NAME"),
        "USER": (os.getenv("SL_USER")),
        "PASSWORD": (os.getenv("SL_PASSWORD")),
        "HOST": os.getenv("SL_HOST"),
        "PORT": os.getenv("SL_PORT", "5432"),
    },
}

SWAGGER_SETTINGS = {
    "DEFAULT_INFO": "shortlink.urls.openapi_info",
    "SECURITY_DEFINITIONS": {
        "Basic": {"type": "basic"},
        "Bearer": {"type": "apiKey", "name": "Authorization", "in": "header"},
    },
}

# CELERY
CELERY_BROKER_URL = "redis://" + os.getenv("REDIS_HOST") + ":" + os.getenv("REDIS_PORT")
CELERY_RESULT_BACKEND = (
    "redis://" + os.getenv("REDIS_HOST") + ":" + os.getenv("REDIS_PORT")
)
CELERY_TIMEZONE = "Africa/Lagos"
# CELERY_BEAT_SCHEDULE = {
#  'send-notification-every-10min': {
#        'task': 'common.utilities.tasks.resend_welcome_email',
#        'schedule': crontab(minute=0), # execute every hour
#     },
#  'flush-expired-tokens': {
#        'task': 'common.utilities.tasks.flush_expired_tokens',
#        'schedule': crontab(hour=1, minute=0), # 1 AM daily
#     },
#  'delete_empty_log_files': {
#        'task': 'common.utilities.tasks.delete_empty_log_files',
#        'schedule': crontab(hour=0, minute=30), # 12:30 AM daily
#     }
# }

# Email configuration
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND")
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = os.getenv("EMAIL_PORT")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS")

SITE_ID = 1  # for django sites

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {},
    "formatters": {
        "verbose": {
            "format": (
                "[%(asctime)s] %(levelname)s [%(name)s-%(lineno)s] %(module)s "
                "%(message)s"
            ),
            "datefmt": "%d/%b/%Y %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "logs/debug.log",
            "formatter": "verbose",
            "level": "DEBUG",
        },
        "error_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": f"logs/app-{datetime.datetime.now():%Y-%m-%d}-error.log",
            "when": "midnight",
            "backupCount": 10,
            "formatter": "verbose",
            "level": "ERROR",
        },
        "info_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": f"logs/app-{datetime.datetime.now():%Y-%m-%d}-info.log",
            "when": "midnight",
            "backupCount": 10,
            "formatter": "verbose",
            "level": "INFO",
        },
    },
    "loggers": {
        "app": {
            "handlers": ["console", "error_file", "info_file"],
            "level": "INFO",
        },
        "app_debug": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
        },
    },
}


SIMPLE_JWT = {
    "USER_ID_FIELD": "id",
    "AUTH_HEADER_TYPES": ("Bearer",),
    # "ACCESS_TOKEN_LIFETIME": datetime.timedelta(minutes=5),
    "ACCESS_TOKEN_LIFETIME": datetime.timedelta(minutes=8000),  # development
    "REFRESH_TOKEN_LIFETIME": datetime.timedelta(days=1),
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "UPDATE_LAST_LOGIN": True,
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

REST_FRAMEWORK = {
    "NON_FIELD_ERRORS_KEY": "error",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 15,
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.AllowAny",),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.coreapi.AutoSchema",
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        # "rest_framework.renderers.BrowsableAPIRenderer",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.ScopedRateThrottle",
        "common.helpers.AnonLinkCreationThrottle",  # rates defined here already
        "common.helpers.UserLinkCreationThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "50/day",
        "user": "800/day",
    },
}

# Restrict Django admin access to specific IP addresses
ALLOWED_ADMIN_IPS = os.getenv("SL_ALLOWED_ADMIN").split(",")

LOGIN_URL = "/api/vi/auth/login/"
# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Africa/Lagos"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
