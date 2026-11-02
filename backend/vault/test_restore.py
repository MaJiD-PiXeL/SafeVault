"""Only opaque synthetic test envelopes are used by the server-side restore tests."""
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError, connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from .models import NonceReservation, RestoreReceipt, VaultEntry
from .services import create_vault, restore_entries


def encoded(size, byte=1):
    return base64.b64encode(bytes([byte]) * size).decode()


def envelope(byte=1, size=48):
    return {"id": str(uuid.uuid4()), "nonce": encoded(12, byte), "ciphertext": encoded(size, byte)}


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class BackupRestoreAPITests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="restore-owner")
        self.other = get_user_model().objects.create_user(username="restore-other")
        self.vault = create_vault(user=self.owner, vault_id=uuid.uuid4(), kdf_salt=encoded(16), wrap_nonce=encoded(12), wrapped_key=encoded(48))
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.owner, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        self.path = f"/api/vaults/{self.vault.pk}/restores/"
        self.data = {"backup_id": str(uuid.uuid4()), "archive_digest": "a" * 64, "entries": [envelope(2), envelope(3)]}

    def post(self, data=None):
        return self.client.post(self.path, self.data if data is None else data, content_type="application/json", HTTP_X_CSRFTOKEN=self.token)

    def test_restore_adds_new_entries_and_preserves_existing_data(self):
        original = VaultEntry.objects.create(vault=self.vault, nonce=encoded(12, 9), ciphertext=encoded(48, 9))
        response = self.post()
        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.json()["already_restored"])
        self.assertEqual(response.json()["entry_count"], 2)
        self.assertEqual(VaultEntry.objects.count(), 3)
        original.refresh_from_db()
        self.assertEqual(original.ciphertext, encoded(48, 9))
        self.assertEqual(RestoreReceipt.objects.count(), 1)
        self.assertEqual(NonceReservation.objects.count(), 2)
        self.assertEqual(set(VaultEntry.objects.filter(pk__in=[item["id"] for item in self.data["entries"]]).values_list("revision", flat=True)), {1})

    def test_retries_even_with_fresh_envelopes_are_idempotent(self):
        self.assertEqual(self.post().status_code, 201)
        changed = {**self.data, "entries": [envelope(4), envelope(5)]}
        response = self.post(changed)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["already_restored"])
        self.assertEqual(VaultEntry.objects.count(), 2)
        self.assertEqual(NonceReservation.objects.count(), 2)
        receipt = self.client.get(self.path + self.data["backup_id"] + "/")
        self.assertEqual(receipt.status_code, 200)
        self.assertTrue(receipt.json()["already_restored"])

    def test_same_backup_identity_with_changed_digest_or_count_is_a_conflict(self):
        self.post()
        for changes in ({"archive_digest": "b" * 64}, {"entries": [envelope(4)]}):
            self.assertEqual(self.post({**self.data, **changes}).status_code, 409)
        self.assertEqual(VaultEntry.objects.count(), 2)

    def test_failed_batch_does_not_insert_any_rows_or_reserve_any_nonces(self):
        with patch("vault.services.VaultEntry.objects.bulk_create", side_effect=IntegrityError("synthetic failure")):
            self.assertEqual(self.post().status_code, 409)
        self.assertEqual(VaultEntry.objects.count(), 0)
        self.assertEqual(NonceReservation.objects.count(), 0)
        self.assertEqual(RestoreReceipt.objects.count(), 0)

    def test_conflicting_ids_and_nonces_never_overwrite_existing_records(self):
        self.post()
        for item in ({**envelope(5), "id": self.data["entries"][0]["id"]}, {**envelope(5), "nonce": self.data["entries"][0]["nonce"]}):
            data = {**self.data, "backup_id": str(uuid.uuid4()), "entries": [item]}
            self.assertEqual(self.post(data).status_code, 409)
        self.assertEqual(VaultEntry.objects.count(), 2)
        self.assertEqual(RestoreReceipt.objects.count(), 1)

    def test_duplicate_batch_id_or_nonce_is_rejected_before_writing(self):
        for field in ("id", "nonce"):
            data = {**self.data, "entries": [self.data["entries"][0], {**self.data["entries"][1], field: self.data["entries"][0][field]}]}
            self.assertEqual(self.post(data).status_code, 409)
        self.assertEqual(VaultEntry.objects.count(), 0)
        self.assertEqual(NonceReservation.objects.count(), 0)

    def test_authentication_csrf_and_cross_account_isolation(self):
        self.post()
        self.assertEqual(Client().get(self.path + self.data["backup_id"] + "/").status_code, 403)
        self.assertEqual(self.client.post(self.path, self.data, content_type="application/json").status_code, 403)
        self.client.force_login(self.other, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        self.assertEqual(self.post().status_code, 404)
        self.assertEqual(self.client.get(self.path + self.data["backup_id"] + "/").status_code, 404)
        self.assertEqual(VaultEntry.objects.count(), 2)

    def test_plaintext_unknown_fields_invalid_encoding_and_empty_batches_are_rejected(self):
        for changes in ({"password": "must not be accepted"}, {"entries": []}, {"archive_digest": "not a digest"},
                        {"entries": [{**envelope(), "title": "must not be accepted"}]}, {"entries": [{**envelope(), "ciphertext": "plaintext"}]}):
            response = self.post({**self.data, **changes})
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("must not be accepted", response.content.decode())
        self.assertEqual(VaultEntry.objects.count(), 0)

    def test_restore_limits_are_atomic_and_normal_writes_cannot_exceed_capacity(self):
        with patch("vault.services.MAX_VAULT_ENTRIES", 1):
            self.assertEqual(self.post().status_code, 400)
        with patch("vault.services.MAX_VAULT_CIPHERTEXT_SIZE", 1):
            self.assertEqual(self.post().status_code, 400)
        self.assertEqual(NonceReservation.objects.count(), 0)
        with patch("vault.services.MAX_VAULT_ENTRIES", 0):
            response = self.client.post(f"/api/vaults/{self.vault.pk}/entries/", envelope(2), content_type="application/json", HTTP_X_CSRFTOKEN=self.token)
            self.assertEqual(response.status_code, 400)
        self.assertEqual(VaultEntry.objects.count(), 0)

    def test_only_restore_accepts_larger_bounded_json_batches(self):
        data = {**self.data, "entries": [envelope(index, 40000) for index in (2, 3, 4)]}
        response = self.post(data)
        self.assertEqual(response.status_code, 201, response.content[:600])
        normal = self.client.post(f"/api/vaults/{self.vault.pk}/entries/", data, content_type="application/json", HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(normal.status_code, 400)

    @override_settings(AUTH_REQUEST_LIMITS={"restore": (1, 3600)})
    def test_restore_rate_limit_counts_malformed_requests_before_parsing(self):
        self.assertEqual(self.post({"unexpected": True}).status_code, 400)
        self.assertEqual(self.post().status_code, 429)
        self.assertEqual(VaultEntry.objects.count(), 0)


class ConcurrentRestoreTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_identical_imports_commit_once(self):
        user = get_user_model().objects.create_user(username="parallel-restore")
        vault = create_vault(user=user, vault_id=uuid.uuid4(), kdf_salt=encoded(16), wrap_nonce=encoded(12), wrapped_key=encoded(48))
        backup_id = uuid.uuid4()
        barrier = Barrier(2)

        def attempt(index):
            try:
                actor = get_user_model().objects.get(pk=user.pk)
                barrier.wait(timeout=10)
                _, repeated = restore_entries(user=actor, vault_id=vault.pk, backup_id=backup_id, archive_digest="a" * 64, entries=[envelope(index)])
                return repeated
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            result = list(executor.map(attempt, (2, 3)))
        self.assertCountEqual(result, [False, True])
        self.assertEqual(VaultEntry.objects.count(), 1)
        self.assertEqual(NonceReservation.objects.count(), 1)
        self.assertEqual(RestoreReceipt.objects.count(), 1)
