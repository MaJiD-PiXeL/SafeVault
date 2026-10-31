"""Isolated tests: never connect to or modify a developer's PostgreSQL vault."""
import os

os.environ.setdefault("DJANGO_SECRET_KEY", "safevault-tests-only-secret-key")

from .settings import *  # noqa: F403

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
