"""Opaque, versioned storage. No master password or plaintext entry fields."""
import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from .validators import Base64Bytes


class ValidatedModel(models.Model):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class OwnedVaultQuerySet(models.QuerySet):
    def for_user(self, user):
        if not user or not user.is_authenticated or not user.is_active:
            return self.none()
        return self.filter(owner=user)


class Vault(ValidatedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="vaults")
    format_version = models.PositiveSmallIntegerField(default=1, choices=[(1, "Version 1")])
    cipher = models.CharField(max_length=16, default="AES-256-GCM", choices=[("AES-256-GCM", "AES-256-GCM")])
    kdf = models.CharField(max_length=16, default="argon2id", choices=[("argon2id", "Argon2id")])
    kdf_version = models.PositiveSmallIntegerField(default=19, choices=[(19, "Argon2 v1.3")])
    kdf_memory_kib = models.PositiveIntegerField(default=65536, choices=[(65536, "64 MiB")])
    kdf_iterations = models.PositiveSmallIntegerField(default=3, choices=[(3, "3 passes")])
    kdf_parallelism = models.PositiveSmallIntegerField(default=4, choices=[(4, "4 lanes")])
    kdf_salt = models.CharField(max_length=24, validators=[Base64Bytes(16, 16)])
    wrap_nonce = models.CharField(max_length=16, validators=[Base64Bytes(12, 12)])
    wrapped_key = models.CharField(max_length=64, validators=[Base64Bytes(48, 48)])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OwnedVaultQuerySet.as_manager()

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    format_version=1, cipher="AES-256-GCM", kdf="argon2id",
                    kdf_version=19, kdf_memory_kib=65536, kdf_iterations=3, kdf_parallelism=4,
                ),
                name="vault_supported_crypto_v1",
            ),
        ]

    def __str__(self):
        return f"Vault {self.pk}"


class OwnedEntryQuerySet(models.QuerySet):
    def for_user(self, user):
        if not user or not user.is_authenticated or not user.is_active:
            return self.none()
        return self.filter(vault__owner=user)


class VaultEntry(ValidatedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE, related_name="entries")
    nonce = models.CharField(max_length=16, validators=[Base64Bytes(12, 12)])
    ciphertext = models.TextField(validators=[Base64Bytes(17, 65552)])
    revision = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OwnedEntryQuerySet.as_manager()

    class Meta:
        indexes = [models.Index(fields=["vault", "-updated_at", "id"], name="entry_vault_updated_idx")]
        constraints = [
            models.CheckConstraint(condition=models.Q(revision__gte=1), name="entry_revision_positive"),
            models.CheckConstraint(condition=~models.Q(ciphertext=""), name="entry_ciphertext_not_empty"),
            models.UniqueConstraint(fields=["vault", "nonce"], name="entry_vault_nonce_unique"),
        ]

    def __str__(self):
        return f"Vault entry {self.pk}"


class NonceReservation(ValidatedModel):
    """Keep used entry nonces even after edits/deletion, for this vault key's lifetime."""
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE, related_name="nonce_reservations")
    nonce = models.CharField(max_length=16, validators=[Base64Bytes(12, 12)])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["vault", "nonce"], name="used_vault_nonce_unique")]


class SecuritySettings(ValidatedModel):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="vault_security")
    auto_lock_seconds = models.PositiveIntegerField(default=300, validators=[MinValueValidator(60), MaxValueValidator(3600)])
    lock_on_hidden = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.CheckConstraint(
            condition=models.Q(auto_lock_seconds__gte=60, auto_lock_seconds__lte=3600),
            name="settings_auto_lock_bounds",
        )]
