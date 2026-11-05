"""Additional deployment checks; diagnostics never include configuration values."""
from email.utils import parseaddr
from urllib.parse import urlsplit

from django.conf import settings
from django.core.checks import Error, Tags, register
from django.core.exceptions import ValidationError
from django.core.validators import validate_email


def secure_origin(origin):
    try:
        parsed = urlsplit(origin)
        port = parsed.port
        return (
            parsed.scheme == "https" and bool(parsed.hostname)
            and parsed.geturl() == origin and "\\" not in origin
            and not any(character.isspace() for character in origin)
            and "*" not in parsed.hostname
            and parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1"}
            and parsed.username is None and parsed.password is None
            and not parsed.path and not parsed.query and not parsed.fragment
            and (port is None or 1 <= port <= 65535)
        )
    except (ValueError, TypeError):
        return False


def valid_sender(sender):
    if "\r" in sender or "\n" in sender:
        return False
    _, address = parseaddr(sender)
    try:
        validate_email(address)
    except ValidationError:
        return False
    return address.rsplit("@", 1)[-1].lower() != "localhost"


@register(Tags.security, deploy=True)
def production_configuration(app_configs, **kwargs):
    errors = []
    if not settings.PRODUCTION:
        errors.append(Error("Run deployment checks with DJANGO_ENV=production.", id="safevault.E001"))
    if not settings.ALLOWED_HOSTS or any(
        "*" in host or host.startswith(".") or host.lower() in {"localhost", "127.0.0.1", "[::1]"}
        for host in settings.ALLOWED_HOSTS
    ):
        errors.append(Error("Set explicit production hostnames in DJANGO_ALLOWED_HOSTS; remove development and wildcard hosts.", id="safevault.E002"))
    for name, code in [("CORS_ALLOWED_ORIGINS", "safevault.E003"), ("CSRF_TRUSTED_ORIGINS", "safevault.E004")]:
        if any(not secure_origin(origin) for origin in getattr(settings, name)):
            errors.append(Error(f"{name} must contain only explicit HTTPS origins without paths, credentials or development hosts.", id=code))
    if settings.DEBUG or not all((settings.SESSION_COOKIE_SECURE, settings.CSRF_COOKIE_SECURE, settings.SECURE_SSL_REDIRECT)):
        errors.append(Error("Production requires DEBUG=False, secure session/CSRF cookies and HTTPS redirects.", id="safevault.E005"))
    mailer = settings.MAILERS.get("default", {})
    if mailer.get("BACKEND") == "django.core.mail.backends.smtp.EmailBackend" and not mailer.get("OPTIONS", {}).get("host", "").strip():
        errors.append(Error("Set DJANGO_SMTP_HOST for production email delivery.", id="safevault.E006"))
    if not secure_origin(settings.ACCOUNT_LINK_ORIGIN):
        errors.append(Error("Set DJANGO_ACCOUNT_LINK_ORIGIN to the public HTTPS frontend origin.", id="safevault.E007"))
    if not valid_sender(settings.DEFAULT_FROM_EMAIL):
        errors.append(Error("Set DJANGO_FROM_EMAIL to a sender address accepted by the mail provider.", id="safevault.E008"))
    return errors
