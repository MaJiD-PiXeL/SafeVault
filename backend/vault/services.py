"""Owner-scoped persistence boundary; HTTP/auth and decryption are separate phases."""
from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib.auth import get_user_model
from django.db import transaction

from .models import NonceReservation, SecuritySettings, Vault, VaultEntry


class RevisionConflict(Exception):
    """A client attempted to overwrite a newer encrypted entry."""


class NonceConflict(ValidationError):
    """A nonce previously submitted under this vault key cannot be reused."""


def _require_user(user):
    if not user or not user.is_authenticated or not user.is_active:
        raise PermissionDenied("Authentication required.")


@transaction.atomic
def create_vault(*, user, vault_id, kdf_salt, wrap_nonce, wrapped_key):
    _require_user(user)
    get_user_model().objects.select_for_update().get(pk=user.pk)
    if Vault.objects.for_user(user).count() >= 10:
        raise ValidationError("Vault limit reached.")
    vault = Vault.objects.create(
        id=vault_id, owner=user, kdf_salt=kdf_salt, wrap_nonce=wrap_nonce, wrapped_key=wrapped_key,
    )
    SecuritySettings.objects.get_or_create(user=user)
    return vault


def list_entries(*, user, vault_id):
    _require_user(user)
    vault = Vault.objects.for_user(user).get(pk=vault_id)
    return VaultEntry.objects.for_user(user).filter(vault=vault).order_by("-updated_at", "id")


@transaction.atomic
def create_entry(*, user, vault_id, entry_id, nonce, ciphertext):
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    # The client generates the UUID before encryption so it can bind it as AAD.
    entry = VaultEntry(id=entry_id, vault=vault, nonce=nonce, ciphertext=ciphertext)
    if NonceReservation.objects.filter(vault=vault, nonce=nonce).exists():
        raise NonceConflict("Nonce already used.")
    entry.full_clean()
    NonceReservation.objects.create(vault=vault, nonce=nonce)
    entry.save(force_insert=True)
    return entry


@transaction.atomic
def update_entry(*, user, entry_id, expected_revision, nonce, ciphertext):
    _require_user(user)
    entry = VaultEntry.objects.for_user(user).select_for_update().get(pk=entry_id)
    if type(expected_revision) is not int or expected_revision != entry.revision:
        raise RevisionConflict("The entry changed. Reload it before saving.")
    entry.nonce = nonce
    entry.ciphertext = ciphertext
    entry.revision += 1
    # Reservations survive replacing an entry's ciphertext and deleting the entry.
    if NonceReservation.objects.filter(vault=entry.vault, nonce=nonce).exists():
        raise NonceConflict("Nonce already used. Encrypt again with a fresh nonce.")
    entry.full_clean()
    NonceReservation.objects.create(vault=entry.vault, nonce=nonce)
    entry.save(update_fields=["nonce", "ciphertext", "revision", "updated_at"])
    return entry


@transaction.atomic
def delete_entry(*, user, entry_id, expected_revision):
    _require_user(user)
    entry = VaultEntry.objects.for_user(user).select_for_update().get(pk=entry_id)
    if type(expected_revision) is not int or expected_revision != entry.revision:
        raise RevisionConflict("The entry changed. Reload it before deleting.")
    entry.delete()
