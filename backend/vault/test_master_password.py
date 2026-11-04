"""Wrapper updates use synthetic bytes and never receive a plaintext password."""
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from django.contrib.auth import get_user_model
from django.db import connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from .models import NonceReservation, RestoreReceipt, Vault, VaultEntry
from .services import (RevisionConflict, change_master_password, create_entry,
                       create_vault, delete_entry)


def encoded(size, byte):
    return base64.b64encode(bytes([byte]) * size).decode()


def replacement(vault, byte=9):
    return {"expected_kdf_salt": vault.kdf_salt, "expected_wrap_nonce": vault.wrap_nonce,
            "expected_wrapped_key": vault.wrapped_key, "kdf_salt": encoded(16, byte),
            "wrap_nonce": encoded(12, byte), "wrapped_key": encoded(48, byte)}


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class MasterPasswordAPITests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="wrapper-owner")
        self.other = get_user_model().objects.create_user(username="wrapper-other")
        self.vault = create_vault(user=self.owner, vault_id=uuid.uuid4(), kdf_salt=encoded(16, 1),
                                  wrap_nonce=encoded(12, 1), wrapped_key=encoded(48, 1))
        for byte in (2, 3):
            entry = create_entry(user=self.owner, vault_id=self.vault.pk, entry_id=uuid.uuid4(),
                                 nonce=encoded(12, byte), ciphertext=encoded(48, byte))
        delete_entry(user=self.owner, entry_id=entry.pk, expected_revision=1)
        RestoreReceipt.objects.create(vault=self.vault, backup_id=uuid.uuid4(), archive_digest="a" * 64, entry_count=1)
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.owner, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        self.path = f"/api/vaults/{self.vault.pk}/master-password/"
        self.data = replacement(self.vault)

    def post(self, data=None):
        return self.client.post(self.path, self.data if data is None else data,
                                content_type="application/json", HTTP_X_CSRFTOKEN=self.token)

    def test_changes_only_wrapper_preserving_active_trash_nonces_receipts_and_account(self):
        entries = list(VaultEntry.objects.order_by("pk").values())
        nonces = list(NonceReservation.objects.order_by("pk").values())
        receipts = list(RestoreReceipt.objects.values())
        created_at = self.vault.created_at
        account_password = self.owner.password
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIn("Cookie", response["Vary"])
        self.vault.refresh_from_db()
        self.owner.refresh_from_db()
        for field in ("kdf_salt", "wrap_nonce", "wrapped_key"):
            self.assertEqual(getattr(self.vault, field), self.data[field])
            self.assertEqual(response.json()[field], self.data[field])
        self.assertEqual(self.vault.created_at, created_at)
        self.assertEqual(self.owner.password, account_password)
        self.assertEqual(list(VaultEntry.objects.order_by("pk").values()), entries)
        self.assertEqual(list(NonceReservation.objects.order_by("pk").values()), nonces)
        self.assertEqual(list(RestoreReceipt.objects.values()), receipts)

    def test_stale_requests_cannot_overwrite_a_new_wrapper_or_be_replayed(self):
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(self.post().status_code, 409)
        self.assertEqual(self.post({**self.data, "kdf_salt": encoded(16, 8)}).status_code, 409)
        self.assertEqual(Vault.objects.get(pk=self.vault.pk).kdf_salt, self.data["kdf_salt"])

    def test_every_expected_wrapper_field_is_checked(self):
        for name, size in (("expected_kdf_salt", 16), ("expected_wrap_nonce", 12), ("expected_wrapped_key", 48)):
            with self.subTest(name=name):
                self.assertEqual(self.post({**self.data, name: encoded(size, 7)}).status_code, 409)

    def test_plaintext_owner_profile_and_other_unknown_fields_are_rejected(self):
        for name in ("current_password", "new_password", "master_password", "owner", "id", "cipher", "kdf_iterations"):
            with self.subTest(name=name):
                self.assertEqual(self.post({**self.data, name: "must not be accepted"}).status_code, 400)
        self.vault.refresh_from_db()
        self.assertEqual(self.vault.kdf_salt, self.data["expected_kdf_salt"])

    def test_all_fields_are_required_and_strictly_encoded(self):
        for name in self.data:
            with self.subTest(name=name):
                self.assertEqual(self.post({key: value for key, value in self.data.items() if key != name}).status_code, 400)
                for value in (None, True, 3, "bad", "", self.data[name] + "\n"):
                    self.assertEqual(self.post({**self.data, name: value}).status_code, 400)

    def test_reusing_any_previous_wrapper_component_is_rejected_atomically(self):
        for name in ("kdf_salt", "wrap_nonce", "wrapped_key"):
            self.assertEqual(self.post({**self.data, name: getattr(self.vault, name)}).status_code, 400)
        self.vault.refresh_from_db()
        self.assertEqual(self.vault.wrapped_key, self.data["expected_wrapped_key"])

    def test_authentication_csrf_ownership_and_missing_vault(self):
        self.assertEqual(Client().post(self.path, self.data, content_type="application/json").status_code, 403)
        self.assertEqual(self.client.post(self.path, self.data, content_type="application/json").status_code, 403)
        self.assertEqual(self.client.get(self.path).status_code, 405)
        self.client.force_login(self.other, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        self.assertEqual(self.post({}).status_code, 404)
        self.path = f"/api/vaults/{uuid.uuid4()}/master-password/"
        self.assertEqual(self.post().status_code, 404)


class ConcurrentMasterPasswordTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_only_one_change_can_commit_from_the_same_wrapper(self):
        owner = get_user_model().objects.create_user(username="wrapper-race")
        vault = create_vault(user=owner, vault_id=uuid.uuid4(), kdf_salt=encoded(16, 1),
                             wrap_nonce=encoded(12, 1), wrapped_key=encoded(48, 1))
        barrier = Barrier(2)

        def attempt(byte):
            try:
                user = get_user_model().objects.get(pk=owner.pk)
                barrier.wait(timeout=10)
                try:
                    change_master_password(user=user, vault_id=vault.pk, **replacement(vault, byte))
                    return "committed"
                except RevisionConflict:
                    return "conflict"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(attempt, [8, 9])), ["committed", "conflict"])
        vault.refresh_from_db()
        self.assertIn(vault.kdf_salt, (encoded(16, 8), encoded(16, 9)))
