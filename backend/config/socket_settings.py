"""Production settings for the bundled Caddy and Gunicorn Unix socket."""
from .settings import *  # noqa: F403

if not PRODUCTION:  # noqa: F405
    raise RuntimeError("The socket deployment requires DJANGO_ENV=production.")

TRUST_UNIX_PROXY = True
