"""Opt-in integration suite in a fresh, uniquely named PostgreSQL test database."""
from copy import deepcopy
from uuid import uuid4

from .settings import *  # noqa: F403

DATABASES = deepcopy(DATABASES)  # noqa: F405
DATABASES["default"]["TEST"] = {"NAME": f"test_velnar_{uuid4().hex}"}
