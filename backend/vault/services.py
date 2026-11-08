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


class KeyVersionConflict(RevisionConflict):
    """The operation was prepared under a different data key."""


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
    _check_wrapper(vault, (expected_kdf_salt, expected_wrap_nonce, expected_wrapped_key),
                   (kdf_salt, wrap_nonce, wrapped_key))
    vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key = kdf_salt, wrap_nonce, wrapped_key
    vault.save(update_fields=["kdf_salt", "wrap_nonce", "wrapped_key", "updated_at"])
    return vault


def _check_wrapper(vault, expected, replacement=None):
    current = (vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key)
    if expected != current:
        raise RevisionConflict("The vault key wrapper changed. Reload before trying again.")
    if replacement is not None and any(old == new for old, new in zip(current, replacement)):
        raise ValidationError("A fresh salt, nonce and wrapped key are required.")


def _check_key_version(vault, expected_key_version):
    if vault.key_version != expected_key_version:
        raise KeyVersionConflict("The vault encryption key changed. Unlock the vault again.")


def _recovery_pair(envelope):
    return (None, None) if envelope is None else (envelope["nonce"], envelope["wrapped_key"])


def _check_recovery(vault, expected_recovery):
    if (vault.recovery_nonce, vault.recovery_wrapped_key) != _recovery_pair(expected_recovery):
        raise RevisionConflict("The vault recovery key changed. Reload before trying again.")


@transaction.atomic
def setup_recovery(*, user, vault_id, expected_key_version, expected_kdf_salt, expected_wrap_nonce,
                   expected_wrapped_key, expected_recovery, recovery):
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    _check_key_version(vault, expected_key_version)
    _check_wrapper(vault, (expected_kdf_salt, expected_wrap_nonce, expected_wrapped_key))
    _check_recovery(vault, expected_recovery)
    nonce, wrapped_key = _recovery_pair(recovery)
    if recovery is not None and (nonce == vault.recovery_nonce or wrapped_key == vault.recovery_wrapped_key):
        raise ValidationError("A fresh recovery wrapper is required.")
    vault.recovery_nonce, vault.recovery_wrapped_key = nonce, wrapped_key
    vault.save(update_fields=["recovery_nonce", "recovery_wrapped_key", "updated_at"])
    return vault


@transaction.atomic
def recover_vault(*, user, vault_id, expected_key_version, expected_kdf_salt, expected_wrap_nonce,
                  expected_wrapped_key, expected_recovery, kdf_salt, wrap_nonce, wrapped_key):
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    _check_key_version(vault, expected_key_version)
    _check_wrapper(vault, (expected_kdf_salt, expected_wrap_nonce, expected_wrapped_key), (kdf_salt, wrap_nonce, wrapped_key))
    if expected_recovery is None:
        raise ValidationError("An active recovery wrapper is required.")
    _check_recovery(vault, expected_recovery)
    vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key = kdf_salt, wrap_nonce, wrapped_key
    vault.recovery_nonce = vault.recovery_wrapped_key = None
    vault.save(update_fields=["kdf_salt", "wrap_nonce", "wrapped_key", "recovery_nonce", "recovery_wrapped_key", "updated_at"])
    return vault


@transaction.atomic
def rotate_key(*, user, vault_id, expected_key_version, expected_entries_version, expected_kdf_salt,
               expected_wrap_nonce, expected_wrapped_key, kdf_salt, wrap_nonce, wrapped_key, entries):
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    _check_key_version(vault, expected_key_version)
    if vault.entries_version != expected_entries_version:
        raise RevisionConflict("The vault changed during rotation.")
    _check_wrapper(vault, (expected_kdf_salt, expected_wrap_nonce, expected_wrapped_key),
                   (kdf_salt, wrap_nonce, wrapped_key))

    # The caller supplies strictly validated opaque envelopes. Lock order is the same
    # as every other writer, so this is the exact snapshot or the request fails.
    replacements = {item["id"]: item for item in entries}
    rows = list(vault.entries.only("id", "nonce", "ciphertext"))
    if len(entries) != len(replacements) or replacements.keys() != {row.pk for row in rows}:
        raise ValidationError("Rotation must include every entry, including Trash, exactly once.")
    nonces = {item["nonce"] for item in entries}
    if (len(nonces) != len(rows) or any(row.nonce in nonces for row in rows)
            or vault.nonce_reservations.filter(nonce__in=nonces).exists()):
        raise NonceConflict("Rotation requires fresh entry nonces.")
    for row in rows:
        item = replacements[row.pk]
        if item["ciphertext"] == row.ciphertext or len(item["ciphertext"]) != len(row.ciphertext):
            raise ValidationError("Rotation requires new ciphertext of the same size.")
        row.nonce, row.ciphertext = item["nonce"], item["ciphertext"]
    # Keep historical nonce reservations and backup receipts across rotations.
    NonceReservation.objects.bulk_create([NonceReservation(vault=vault, nonce=nonce) for nonce in nonces], batch_size=100)
    # Limit statement size and memory even when entries approach the ciphertext limit.
    for start in range(0, len(rows), 32):
        VaultEntry.objects.bulk_update(rows[start:start + 32], ["nonce", "ciphertext"])
    vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key = kdf_salt, wrap_nonce, wrapped_key
    vault.recovery_nonce = vault.recovery_wrapped_key = None
    vault.key_version += 1
    vault.entries_version = uuid.uuid4()
    vault.save(update_fields=["kdf_salt", "wrap_nonce", "wrapped_key", "recovery_nonce", "recovery_wrapped_key",
                              "key_version", "entries_version", "updated_at"])
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


def _locked_entry(user, entry_id, expected_key_version):
    # All writers take the vault lock first, including capacity checks and restores.
    reference = VaultEntry.objects.for_user(user).only("vault_id").get(pk=entry_id)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=reference.vault_id)
    _check_key_version(vault, expected_key_version)
    return VaultEntry.objects.for_user(user).select_for_update().get(pk=entry_id)


def _check_versions(entry, expected_revision, expected_state_version):
    if (type(expected_revision) is not int or expected_revision != entry.revision
            or type(expected_state_version) is not int or expected_state_version != entry.state_version):
        raise RevisionConflict("The entry changed. Refresh before trying again.")


def _change_entries_version(vault_id):
    # Every entry write holds the vault row lock and commits this token with its rows.
    Vault.objects.filter(pk=vault_id).update(entries_version=uuid.uuid4())


@transaction.atomic
def create_entry(*, user, vault_id, entry_id, nonce, ciphertext, expected_key_version=1):
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    _check_key_version(vault, expected_key_version)
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
def update_entry(*, user, entry_id, expected_revision, nonce, ciphertext, expected_state_version=1, expected_key_version=1):
    _require_user(user)
    entry = _locked_entry(user, entry_id, expected_key_version)
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
def delete_entry(*, user, entry_id, expected_revision, expected_state_version=1, expected_key_version=1):
    """Move an active encrypted entry to Trash; content and its AAD stay unchanged."""
    _require_user(user)
    entry = _locked_entry(user, entry_id, expected_key_version)
    _check_versions(entry, expected_revision, expected_state_version)
    if entry.deleted_at is not None or entry.state_version >= 2147483647:
        raise RevisionConflict("The entry state changed. Refresh before trying again.")
    entry.deleted_at = timezone.now()
    entry.state_version += 1
    entry.save(update_fields=["deleted_at", "state_version", "updated_at"])
    _change_entries_version(entry.vault_id)
    return entry


@transaction.atomic
def restore_entry(*, user, entry_id, expected_revision, expected_state_version, expected_key_version=1):
    _require_user(user)
    entry = _locked_entry(user, entry_id, expected_key_version)
    _check_versions(entry, expected_revision, expected_state_version)
    if entry.deleted_at is None or entry.state_version >= 2147483647:
        raise RevisionConflict("The entry state changed. Refresh before trying again.")
    entry.deleted_at = None
    entry.state_version += 1
    entry.save(update_fields=["deleted_at", "state_version", "updated_at"])
    _change_entries_version(entry.vault_id)
    return entry


@transaction.atomic
def purge_entry(*, user, entry_id, expected_revision, expected_state_version, expected_key_version=1):
    _require_user(user)
    entry = _locked_entry(user, entry_id, expected_key_version)
    _check_versions(entry, expected_revision, expected_state_version)
    if entry.deleted_at is None:
        raise RevisionConflict("Only entries in Trash can be permanently deleted.")
    # Nonce reservations and backup restore receipts deliberately survive purge.
    entry.delete()
    _change_entries_version(entry.vault_id)


@transaction.atomic
def restore_entries(*, user, vault_id, backup_id, archive_digest, entries, expected_key_version=1):
    """Add all fresh envelopes or none. Repeating one archive cannot duplicate it."""
    _require_user(user)
    vault = Vault.objects.for_user(user).select_for_update().get(pk=vault_id)
    _check_key_version(vault, expected_key_version)
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
