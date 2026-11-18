"""RFC 6238 TOTP. Call mutation functions while holding the user's row lock."""
import base64
import hashlib
import hmac
import secrets
import struct
from datetime import timedelta
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.views.decorators.debug import sensitive_variables

from .models import AccountSession, SecondFactor

SESSION_PROOF = "safevault_mfa_verified"


def mark_verified(request, factor):
    # Bind proof to this enrollment, not just the user or a reusable boolean.
    request.session[SESSION_PROOF] = factor_stamp(factor)


def factor_stamp(factor):
    return salted_hmac("safevault.mfa.session.v1", f"{factor.user_id}:{factor.pk}:{factor.encrypted_secret}",
                       algorithm="sha256").hexdigest()


def session_verified(request):
    proof = request.session.get(SESSION_PROOF)
    if not isinstance(proof, str):
        return False
    factor = SecondFactor.objects.filter(user=request.user, enabled=True).first()
    return bool(factor and constant_time_compare(proof, factor_stamp(factor)))


def cipher():
    # Separate the encryption domain from all Django signing uses. Fallbacks
    # permit a controlled Django key rotation followed by seed re-encryption.
    keys = [settings.SECRET_KEY, *settings.SECRET_KEY_FALLBACKS]
    return MultiFernet([Fernet(base64.urlsafe_b64encode(
        hmac.digest(key.encode(), b"safevault.totp.encryption.v1", "sha256"))) for key in keys])


def hotp(secret, counter, digits=6):
    key = base64.b32decode(secret)
    digest = hmac.digest(key, struct.pack(">Q", counter), "sha1")
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(value % (10 ** digits)).zfill(digits)


@sensitive_variables()
def consume(factor, code, *, allow_recovery=True):
    if not isinstance(code, str) or len(code) > 64:
        return False
    if len(code) == 6 and code.isascii() and code.isdigit():
        try:
            secret = cipher().decrypt(factor.encrypted_secret.encode()).decode()
        except (InvalidToken, UnicodeError, ValueError):
            return False
        counter = int(timezone.now().timestamp()) // 30
        for step in (counter, counter - 1, counter + 1):
            if step >= 0 and step > factor.last_counter and hmac.compare_digest(hotp(secret, step), code):
                factor.last_counter = step
                factor.save(update_fields=["last_counter"])
                return True
    if allow_recovery:
        normalized = code.replace("-", "").lower()
        if len(normalized) == 32 and all(char in "0123456789abcdef" for char in normalized):
            digest = hashlib.sha256(normalized.encode()).hexdigest()
            for stored in factor.recovery_hashes:
                if hmac.compare_digest(stored, digest):
                    factor.recovery_hashes = [item for item in factor.recovery_hashes if item != stored]
                    factor.save(update_fields=["recovery_hashes"])
                    return True
    return False


@sensitive_variables()
def begin(user):
    existing = SecondFactor.objects.filter(user=user).first()
    if existing and existing.enabled:
        return None
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    SecondFactor.objects.update_or_create(user=user, defaults={
        "encrypted_secret": cipher().encrypt(secret.encode()).decode(),
        "enabled": False, "created_at": timezone.now(), "last_counter": -1, "recovery_hashes": [],
    })
    label = quote(f"NEXORA SafeVault:{user.username}", safe="")
    return {"secret": secret, "uri": f"otpauth://totp/{label}?" + urlencode({
        "secret": secret, "issuer": "NEXORA SafeVault", "algorithm": "SHA1", "digits": 6, "period": 30,
    })}


@sensitive_variables()
def enable(factor, code):
    if factor.enabled or factor.created_at < timezone.now() - timedelta(minutes=10):
        return None
    if not consume(factor, code, allow_recovery=False):
        return None
    factor.enabled = True
    factor.save(update_fields=["enabled"])
    return new_recovery_codes(factor)


@sensitive_variables()
def new_recovery_codes(factor):
    codes = [secrets.token_hex(16) for _ in range(10)]
    factor.recovery_hashes = [hashlib.sha256(code.encode()).hexdigest() for code in codes]
    factor.save(update_fields=["recovery_hashes"])
    return ["-".join(code[index:index + 8] for index in range(0, 32, 8)) for code in codes]


def revoke_other_sessions(user, current_key):
    keys = AccountSession.objects.filter(user=user).exclude(session_id=current_key).values_list("session_id", flat=True)
    Session.objects.filter(session_key__in=list(keys)).delete()
