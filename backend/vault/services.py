"""Owner-scoped persistence boundary; HTTP/auth and decryption are separate phases."""
import uuid

from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Count, Sum
from django.db.models.functions import Length
from django.utils import timezone

from .models import NonceReservation, RestoreReceipt, SecuritySettings, Vault, VaultEntry

MAX_VAULT_ENTRIES = 5000
MAX_VAULT_CIPHERTEXT_SIZE = 32 * 1024 * 1024


def _check_capacity(vault, count, size, exclude_id=None):
    existing = vault.entries.all()
    if exclude_id is not None:
        existing = existing.exclude(pk=exclude_id)
    totals = existing.aggregate(count=Count("pk"), size=Sum(Length("ciphertext")))
    if totals["count"] + count > MAX_VAULT_ENTRIES or (totals["size"] or 0) + size > MAX_VAULT_CIPHERTEXT_SIZE:
        raise ValidationError("Vault entry or size limit reached.")


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


@transaction.atomic
def change_master_password(*, user, vault_id, expected_kdf_salt, expected_wrap_nonce,
                           expected_wrapped_key, kdf_salt, wrap_nonce, wrapped_key):
    """Replace only the client-produced wrapper, provided it has not changed."""
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    if (vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key) != (
            expected_kdf_salt, expected_wrap_nonce, expected_wrapped_key):
        raise RevisionConflict("The vault key wrapper changed. Reload before trying again.")
    if kdf_salt == vault.kdf_salt or wrap_nonce == vault.wrap_nonce or wrapped_key == vault.wrapped_key:
        raise ValidationError("A fresh salt, nonce and wrapped key are required.")
    vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key = kdf_salt, wrap_nonce, wrapped_key
    vault.save(update_fields=["kdf_salt", "wrap_nonce", "wrapped_key", "updated_at"])
    return vault


def list_entries(*, user, vault_id, state="active"):
    _require_user(user)
    vault = Vault.objects.for_user(user).get(pk=vault_id)
    entries = VaultEntry.objects.for_user(user).filter(vault=vault)
    if state == "active":
        entries = entries.filter(deleted_at__isnull=True)
    elif state == "trash":
        entries = entries.filter(deleted_at__isnull=False)
    elif state != "all":
        raise ValidationError("Invalid entry state.")
    return entries.order_by("-updated_at", "id")


def _locked_entry(user, entry_id):
    # All writers take the vault lock first, including capacity checks and restores.
    reference = VaultEntry.objects.for_user(user).only("vault_id").get(pk=entry_id)
    Vault.objects.for_user(user).select_for_update().get(pk=reference.vault_id)
    return VaultEntry.objects.for_user(user).select_for_update().get(pk=entry_id)


def _check_versions(entry, expected_revision, expected_state_version):
    if (type(expected_revision) is not int or expected_revision != entry.revision
            or type(expected_state_version) is not int or expected_state_version != entry.state_version):
        raise RevisionConflict("The entry changed. Refresh before trying again.")


def _change_entries_version(vault_id):
    # Every entry write holds the vault row lock and commits this token with its rows.
    Vault.objects.filter(pk=vault_id).update(entries_version=uuid.uuid4())


@transaction.atomic
def create_entry(*, user, vault_id, entry_id, nonce, ciphertext):
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    # The client generates the UUID before encryption so it can bind it as AAD.
    entry = VaultEntry(id=entry_id, vault=vault, nonce=nonce, ciphertext=ciphertext)
    if NonceReservation.objects.filter(vault=vault, nonce=nonce).exists():
        raise NonceConflict("Nonce already used.")
    entry.full_clean()
    _check_capacity(vault, 1, len(entry.ciphertext))
    NonceReservation.objects.create(vault=vault, nonce=nonce)
    entry.save(force_insert=True)
    _change_entries_version(vault_id)
    return entry


@transaction.atomic
def update_entry(*, user, entry_id, expected_revision, nonce, ciphertext, expected_state_version=1):
    _require_user(user)
    entry = _locked_entry(user, entry_id)
    _check_versions(entry, expected_revision, expected_state_version)
    if entry.deleted_at is not None:
        raise RevisionConflict("Restore the entry before editing it.")
    entry.nonce = nonce
    entry.ciphertext = ciphertext
    entry.revision += 1
    # Reservations survive replacing an entry's ciphertext and deleting the entry.
    if NonceReservation.objects.filter(vault=entry.vault, nonce=nonce).exists():
        raise NonceConflict("Nonce already used. Encrypt again with a fresh nonce.")
    entry.full_clean()
    _check_capacity(entry.vault, 1, len(entry.ciphertext), exclude_id=entry.pk)
    NonceReservation.objects.create(vault=entry.vault, nonce=nonce)
    entry.save(update_fields=["nonce", "ciphertext", "revision", "updated_at"])
    _change_entries_version(entry.vault_id)
    return entry


@transaction.atomic
def delete_entry(*, user, entry_id, expected_revision, expected_state_version=1):
    """Move an active encrypted entry to Trash; content and its AAD stay unchanged."""
    _require_user(user)
    entry = _locked_entry(user, entry_id)
    _check_versions(entry, expected_revision, expected_state_version)
    if entry.deleted_at is not None or entry.state_version >= 2147483647:
        raise RevisionConflict("The entry state changed. Refresh before trying again.")
    entry.deleted_at = timezone.now()
    entry.state_version += 1
    entry.save(update_fields=["deleted_at", "state_version", "updated_at"])
    _change_entries_version(entry.vault_id)
    return entry


@transaction.atomic
def restore_entry(*, user, entry_id, expected_revision, expected_state_version):
    _require_user(user)
    entry = _locked_entry(user, entry_id)
    _check_versions(entry, expected_revision, expected_state_version)
    if entry.deleted_at is None or entry.state_version >= 2147483647:
        raise RevisionConflict("The entry state changed. Refresh before trying again.")
    entry.deleted_at = None
    entry.state_version += 1
    entry.save(update_fields=["deleted_at", "state_version", "updated_at"])
    _change_entries_version(entry.vault_id)
    return entry


@transaction.atomic
def purge_entry(*, user, entry_id, expected_revision, expected_state_version):
    _require_user(user)
    entry = _locked_entry(user, entry_id)
    _check_versions(entry, expected_revision, expected_state_version)
    if entry.deleted_at is None:
        raise RevisionConflict("Only entries in Trash can be permanently deleted.")
    # Nonce reservations and backup restore receipts deliberately survive purge.
    entry.delete()
    _change_entries_version(entry.vault_id)


@transaction.atomic
def restore_entries(*, user, vault_id, backup_id, archive_digest, entries):
    """Add all fresh envelopes or none. Repeating one archive cannot duplicate it."""
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    receipt = RestoreReceipt.objects.filter(vault=vault, backup_id=backup_id).first()
    if receipt:
        if receipt.archive_digest != archive_digest or receipt.entry_count != len(entries):
            raise RevisionConflict("Backup identity conflicts with a previous restore.")
        return receipt, True
    if not 1 <= len(entries) <= 5000:
        raise ValidationError("Invalid restore size.")
    rows = [VaultEntry(id=item["id"], vault=vault, nonce=item["nonce"], ciphertext=item["ciphertext"], revision=1) for item in entries]
    for row in rows:
        row.full_clean(exclude=["vault"], validate_unique=False, validate_constraints=False)
    ids = [row.pk for row in rows]
    nonces = [row.nonce for row in rows]
    if len(set(ids)) != len(ids) or len(set(nonces)) != len(nonces):
        raise RevisionConflict("Duplicate encrypted envelopes.")
    if VaultEntry.objects.filter(pk__in=ids).exists() or NonceReservation.objects.filter(vault=vault, nonce__in=nonces).exists():
        raise RevisionConflict("Entry identity or nonce already used.")
    _check_capacity(vault, len(rows), sum(len(row.ciphertext) for row in rows))
    # All fields were validated above; bulk inserts preserve one atomic transaction.
    NonceReservation.objects.bulk_create([NonceReservation(vault=vault, nonce=row.nonce) for row in rows], batch_size=100)
    VaultEntry.objects.bulk_create(rows, batch_size=100)
    receipt = RestoreReceipt.objects.create(vault=vault, backup_id=backup_id, archive_digest=archive_digest, entry_count=len(rows))
    _change_entries_version(vault_id)
    return receipt, False
