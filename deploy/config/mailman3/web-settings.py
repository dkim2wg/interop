import os

# Base settings from mailman-web
from mailman_web.settings.base import *
from mailman_web.settings.mailman import *

BASE_DIR = "/var/lib/mailman3/web"
SECRET_KEY = '__DJANGO_SECRET_KEY__'
ALLOWED_HOSTS = ["mailman.dkim2.com", "localhost", "127.0.0.1"]

MAILMAN_REST_API_URL = "http://localhost:8001"
MAILMAN_REST_API_USER = "restadmin"
MAILMAN_REST_API_PASS = '__MAILMAN_REST_PASS__'

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "mailman-web.db"),
    }
}

STATIC_ROOT = "/var/lib/mailman3/web/static"
STATIC_URL = "/static/"

# Email settings for Django (password reset etc)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "localhost"
EMAIL_PORT = 25

DEFAULT_FROM_EMAIL = "admin@mailman.dkim2.com"
SERVER_EMAIL = "admin@mailman.dkim2.com"

# HyperKitty
HAYSTACK_CONNECTIONS = {
    "default": {
        "ENGINE": "haystack.backends.whoosh_backend.WhooshEngine",
        "PATH": os.path.join(BASE_DIR, "fulltext_index"),
    },
}

# Logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "file": {
            "level": "INFO",
            "class": "logging.FileHandler",
            "filename": "/var/log/mailman3/mailman-web.log",
        },
    },
    "loggers": {
        "django": {"handlers": ["file"], "level": "INFO"},
        "hyperkitty": {"handlers": ["file"], "level": "INFO"},
        "postorius": {"handlers": ["file"], "level": "INFO"},
    },
}
MAILMAN_ARCHIVER_KEY = '__HYPERKITTY_API_KEY__'
