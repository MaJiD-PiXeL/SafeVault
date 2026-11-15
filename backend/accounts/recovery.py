from datetime import timedelta
from smtplib import SMTPException
from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sessions.models import Session
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from .checks import secure_origin
from .models import AccountSession, PasswordResetRequest, RecoveryEmail


class InvalidRecoveryLink(Exception):
    pass


class RecoveryEmailAlreadyVerified(Exception):
    pass


class IncorrectAccountPassword(Exception):
    pass


class EmailDeliveryError(Exception):
    pass


class RecoveryTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "safevault.account-recovery.v1"

    def _make_hash_value(self, user, timestamp):
        address = user.recovery_email
        return repr((user.pk, user.username, user.password, timestamp, address.email, address.verified_at))


class VerificationTokenGenerator(RecoveryTokenGenerator):
    key_salt = "safevault.email-verification.v1"


reset_tokens = RecoveryTokenGenerator()
verification_tokens = VerificationTokenGenerator()
RESET_REQUEST_MAX_AGE = timedelta(minutes=15)
RESET_DELIVERY_RETRY_DELAY = timedelta(minutes=2)


def link_origin():
    origin = settings.ACCOUNT_LINK_ORIGIN
    if secure_origin(origin):
        return origin
    if not settings.PRODUCTION:
        try:
            parsed = urlsplit(origin)
            if parsed.hostname in {"localhost", "127.0.0.1", "::1"} and parsed.scheme == "http":
                host = "[::1]" if parsed.hostname == "::1" else parsed.hostname
                allowed = f"http://{host}:{parsed.port}" if parsed.port else f"http://{host}"
                if origin == allowed:
                    return origin
        except ValueError:
            pass
    raise EmailDeliveryError("Account email links are unavailable.")


@sensitive_variables()
def send_recovery_link(user, *, verify):
    generator = verification_tokens if verify else reset_tokens
    title = "Verify recovery email" if verify else "Reset account password"
    fragment = urlencode({
        "account-action": "verify" if verify else "reset",
        "username": user.username,
        "token": generator.make_token(user),
    })
    link = f"{link_origin()}/#{fragment}"
    minutes = settings.PASSWORD_RESET_TIMEOUT // 60
    body = (
        f"{title} for your SafeVault account. This link expires in {minutes} minutes.\n\n"
        f"{link}\n\n"
        "If you did not request this, you can ignore this message."
    )
    try:
        delivered = send_mail(f"SafeVault — {title}", body, None, [user.recovery_email.email])
    except (OSError, SMTPException, ValueError):
        raise EmailDeliveryError("Account email could not be sent.") from None
    if delivered != 1:
        raise EmailDeliveryError("Account email could not be sent.")


@sensitive_variables()
@transaction.atomic
def enroll_recovery_email(*, user, email, password):
    locked = get_user_model().objects.select_for_update().filter(pk=user.pk, is_active=True).first()
    if locked is None or not locked.check_password(password):
        raise IncorrectAccountPassword
    existing = RecoveryEmail.objects.filter(user=locked).first()
    if existing and existing.verified_at:
        raise RecoveryEmailAlreadyVerified
    address, _ = RecoveryEmail.objects.update_or_create(user=locked, defaults={"email": email})
    locked.recovery_email = address
    return locked


@sensitive_variables()
def _locked_link_user(username, token, *, verify):
    user = get_user_model().objects.select_for_update().filter(username=username, is_active=True).first()
    address = RecoveryEmail.objects.filter(user=user).first() if user and user.has_usable_password() else None
    if not address or bool(address.verified_at) == verify:
        raise InvalidRecoveryLink
    user.recovery_email = address
    generator = verification_tokens if verify else reset_tokens
    if not generator.check_token(user, token):
        raise InvalidRecoveryLink
    return user


@sensitive_variables()
@transaction.atomic
def verify_recovery_email(*, username, token):
    user = _locked_link_user(username, token, verify=True)
    address = user.recovery_email
    address.verified_at = timezone.now()
    address.save(update_fields=["verified_at"])


@sensitive_variables()
@transaction.atomic
def reset_account_password(*, username, token, password):
    user = _locked_link_user(username, token, verify=False)
    validate_password(password, user)
    user.set_password(password)
    user.save(update_fields=["password"])
    keys = list(AccountSession.objects.filter(user=user).values_list("session_id", flat=True))
    Session.objects.filter(session_key__in=keys).delete()
    PasswordResetRequest.objects.filter(username=username).delete()


def dispatch_reset_requests(limit=20):
    now = timezone.now()
    PasswordResetRequest.objects.filter(created_at__lte=now - RESET_REQUEST_MAX_AGE).delete()
    jobs = list(PasswordResetRequest.objects.filter(next_attempt_at__lte=now).order_by("created_at", "pk")[:limit])
    sent = failed = 0
    for job in jobs:
        # A reset racing this attempt either removes the job or invalidates the token's password hash.
        user = get_user_model().objects.select_related("recovery_email").filter(
            username=job.username, is_active=True, recovery_email__verified_at__isnull=False,
        ).first()
        now = timezone.now()
        retry_at = now + RESET_DELIVERY_RETRY_DELAY
        queued = PasswordResetRequest.objects.filter(pk=job.pk)
        # Claim with one update and release the database before talking to SMTP.
        if not queued.filter(next_attempt_at=job.next_attempt_at,
                             created_at__gt=now - RESET_REQUEST_MAX_AGE).update(next_attempt_at=retry_at):
            continue
        if user is not None and user.has_usable_password():
            try:
                send_recovery_link(user, verify=False)
            except EmailDeliveryError:
                failed += 1
                continue
            sent += 1
        queued.filter(next_attempt_at=retry_at).delete()
    return sent, failed
