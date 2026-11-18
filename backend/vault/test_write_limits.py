import base64
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings

from .models import NonceReservation, RestoreReceipt, VaultEntry
from .services import create_entry, create_vault, restore_entries, rotate_key, update_entry


def encoded(size, value=1):
    return base64.b64encode(bytes([value]) * size).decode()


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class WriteLimitsTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="write-budget")
        self.vault = create_vault(user=self.user, vault_id=uuid.uuid4(), kdf_salt=encoded(16), wrap_nonce=encoded(12), wrapped_key=encoded(48))
        self.entry = create_entry(user=self.user, vault_id=self.vault.pk, entry_id=uuid.uuid4(), nonce=encoded(12, 2), ciphertext=encoded(48, 2))
        self.vault.refresh_from_db()

    @patch("vault.services.MAX_VAULT_NONCE_RESERVATIONS", 1)
    def test_update_create_restore_and_rotation_preserve_data_when_history_is_full(self):
        with self.assertRaises(ValidationError):
            update_entry(user=self.user, entry_id=self.entry.pk, expected_revision=1, nonce=encoded(12, 3), ciphertext=encoded(48, 3))
        with self.assertRaises(ValidationError):
            create_entry(user=self.user, vault_id=self.vault.pk, entry_id=uuid.uuid4(), nonce=encoded(12, 3), ciphertext=encoded(48, 3))
        with self.assertRaises(ValidationError):
            restore_entries(user=self.user, vault_id=self.vault.pk, backup_id=uuid.uuid4(), archive_digest="a" * 64,
                            entries=[{"id": uuid.uuid4(), "nonce": encoded(12, 3), "ciphertext": encoded(48, 3)}])
        with self.assertRaises(ValidationError):
            rotate_key(user=self.user, vault_id=self.vault.pk, expected_key_version=1,
                       expected_entries_version=self.vault.entries_version, expected_kdf_salt=self.vault.kdf_salt,
                       expected_wrap_nonce=self.vault.wrap_nonce, expected_wrapped_key=self.vault.wrapped_key,
                       kdf_salt=encoded(16, 4), wrap_nonce=encoded(12, 4), wrapped_key=encoded(48, 4),
                       entries=[{"id": self.entry.pk, "nonce": encoded(12, 4), "ciphertext": encoded(48, 4)}])
        self.entry.refresh_from_db()
        self.vault.refresh_from_db()
        self.assertEqual(self.entry.revision, 1)
        self.assertEqual(self.vault.key_version, 1)
        self.assertEqual(NonceReservation.objects.count(), 1)
        self.assertEqual(VaultEntry.objects.count(), 1)
        self.assertFalse(RestoreReceipt.objects.exists())

    @override_settings(AUTH_REQUEST_LIMITS={"vault-write": (2, 60), "vault-write-hour": (100, 3600)})
    def test_invalid_writes_share_a_user_budget_across_ips_and_leave_reads_available(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        token = client.get("/api/auth/session/").json()["csrfToken"]
        path = f"/api/vaults/{self.vault.pk}/entries/{self.entry.pk}/"
        for ip in ("127.0.0.1", "127.0.0.2"):
            self.assertEqual(client.patch(path, {"bad": "field"}, content_type="application/json", HTTP_X_CSRFTOKEN=token, REMOTE_ADDR=ip).status_code, 400)
        self.assertEqual(client.patch(path, {}, content_type="application/json", HTTP_X_CSRFTOKEN=token, REMOTE_ADDR="127.0.0.3").status_code, 429)
        self.assertEqual(client.get(path).status_code, 200)
