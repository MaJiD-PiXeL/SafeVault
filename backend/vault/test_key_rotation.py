import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from .models import NonceReservation, RestoreReceipt, Vault, VaultEntry
from .services import RevisionConflict, change_master_password, create_entry, create_vault, delete_entry, rotate_key
from .test_master_password import encoded, replacement


def make_vault(user):
    return create_vault(user=user, vault_id=uuid.uuid4(), kdf_salt=encoded(16, 1),
                        wrap_nonce=encoded(12, 1), wrapped_key=encoded(48, 1))


def envelope(byte, entry_id=None):
    return {"id": str(entry_id or uuid.uuid4()), "nonce": encoded(12, byte), "ciphertext": encoded(48, byte)}


def batch(vault, entries):
    return {**replacement(vault), "expected_key_version": vault.key_version,
            "expected_entries_version": str(vault.entries_version), "entries": entries}


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class KeyRotationAPITests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="rotation-owner")
        self.vault = make_vault(self.owner)
        for byte in (2, 3):
            item = envelope(byte)
            create_entry(user=self.owner, vault_id=self.vault.pk, entry_id=item["id"],
                         nonce=item["nonce"], ciphertext=item["ciphertext"])
        self.active, self.trash = self.vault.entries.order_by("created_at")
        self.trash = delete_entry(user=self.owner, entry_id=self.trash.pk, expected_revision=1)
        RestoreReceipt.objects.create(vault=self.vault, backup_id=uuid.uuid4(), archive_digest="a" * 64, entry_count=1)
        self.vault.refresh_from_db()
        self.data = batch(self.vault, [envelope(4, self.active.pk), envelope(5, self.trash.pk)])
        self.base = f"/api/vaults/{self.vault.pk}/"
        self.client = Client(enforce_csrf_checks=True)
        self.login(self.owner)

    def login(self, user):
        self.client.force_login(user, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]

    def write(self, method, suffix, data):
        return getattr(self.client, method)(self.base + suffix, data, content_type="application/json", HTTP_X_CSRFTOKEN=self.token)

    def test_atomic_commit_preserves_metadata_receipts_and_nonce_history(self):
        before = {str(row["id"]): row for row in self.vault.entries.values()}
        version = self.vault.entries_version
        receipts = list(self.vault.restore_receipts.values())
        response = self.write("post", "key-rotation/", self.data)
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response.json()["key_version"], 2)
        self.vault.refresh_from_db()
        self.assertNotEqual(self.vault.entries_version, version)
        self.assertEqual(self.vault.wrapped_key, self.data["wrapped_key"])
        for item in self.data["entries"]:
            row = VaultEntry.objects.values().get(pk=item["id"])
            self.assertEqual(row, {**before[item["id"]], "nonce": item["nonce"], "ciphertext": item["ciphertext"]})
        self.assertEqual(list(self.vault.restore_receipts.values()), receipts)
        self.assertSetEqual(set(self.vault.nonce_reservations.values_list("nonce", flat=True)),
                            {encoded(12, byte) for byte in (2, 3, 4, 5)})
        for suffix in ("entries-version/", "entries/?state=all"):
            snapshot = self.client.get(self.base + suffix).json()
            self.assertEqual(snapshot["key_version"], 2)
            self.assertEqual(snapshot["version"], str(self.vault.entries_version))
        self.assertEqual(self.write("post", "key-rotation/", self.data).status_code, 409)

    def test_every_stale_write_is_rejected_including_legacy_clients(self):
        self.assertEqual(self.write("post", "key-rotation/", self.data).status_code, 200)
        entry = f"entries/{self.active.pk}/"
        trash = f"entries/{self.trash.pk}/"
        revisions = {"expected_revision": 1, "expected_state_version": 1}
        trash_revisions = {**revisions, "expected_state_version": 2}
        new = envelope(6)
        restore = {"backup_id": str(uuid.uuid4()), "archive_digest": "b" * 64, "entries": [envelope(7)]}
        writes = [("post", "entries/", new), ("patch", entry, {**revisions, "nonce": new["nonce"], "ciphertext": new["ciphertext"]}),
                  ("delete", entry, revisions), ("post", trash + "restore/", trash_revisions),
                  ("delete", trash + "purge/", trash_revisions), ("post", "restores/", restore)]
        for method, path, payload in writes:
            with self.subTest(path=path, method=method):
                result = self.write(method, path, payload)
                self.assertEqual(result.status_code, 409, result.json())
                self.assertEqual(result.json()["code"], "vault_key_changed")
        current = {"expected_key_version": 2}
        for method, path, payload, status in [
            ("post", "entries/", new, 201),
            ("patch", entry, {**revisions, "nonce": encoded(12, 8), "ciphertext": new["ciphertext"]}, 200),
            ("delete", entry, {**revisions, "expected_revision": 2}, 200),
            ("post", trash + "restore/", trash_revisions, 200),
            ("delete", entry + "purge/", {**trash_revisions, "expected_revision": 2}, 204),
            ("post", "restores/", restore, 201),
        ]:
            with self.subTest(current_key=path, method=method):
                result = self.write(method, path, {**payload, **current})
                self.assertEqual(result.status_code, status, result.content)

    def test_partial_foreign_duplicate_and_reused_nonce_batches_make_no_changes(self):
        active, trash = self.data["entries"]
        before = list(self.vault.entries.order_by("id").values())
        for entries, status in [([active], 400), ([active, active], 400), ([active, envelope(5)], 400),
                                ([active, {**trash, "nonce": active["nonce"]}], 409),
                                ([active, {**trash, "nonce": self.trash.nonce}], 409),
                                ([active, {**trash, "ciphertext": self.trash.ciphertext}], 400)]:
            with self.subTest(entries=entries):
                self.assertEqual(self.write("post", "key-rotation/", {**self.data, "entries": entries}).status_code, status)
        version = self.vault.entries_version
        self.vault.refresh_from_db()
        self.assertEqual(self.vault.key_version, 1)
        self.assertEqual(self.vault.entries_version, version)
        self.assertEqual(list(self.vault.entries.order_by("id").values()), before)
        self.assertEqual(NonceReservation.objects.filter(vault=self.vault).count(), 2)

    def test_entry_changes_and_password_changes_invalidate_prepared_rotation(self):
        delete_entry(user=self.owner, entry_id=self.active.pk, expected_revision=1)
        self.assertEqual(self.write("post", "key-rotation/", self.data).status_code, 409)

    def test_failure_after_ciphertext_updates_rolls_back_entries_and_nonce_reservations(self):
        before = list(self.vault.entries.order_by("id").values())
        args = {**self.data, "expected_entries_version": self.vault.entries_version,
                "entries": [{**item, "id": uuid.UUID(item["id"])} for item in self.data["entries"]]}
        with patch.object(Vault, "save", side_effect=RuntimeError("Simulated commit failure")):
            with self.assertRaises(RuntimeError):
                rotate_key(user=self.owner, vault_id=self.vault.pk, **args)
        self.assertEqual(list(self.vault.entries.order_by("id").values()), before)
        self.assertEqual(self.vault.nonce_reservations.count(), 2)
        version = self.vault.entries_version
        self.vault.refresh_from_db()
        self.assertEqual(self.vault.entries_version, version)
        self.assertEqual(self.vault.key_version, 1)
        self.vault.refresh_from_db()
        change_master_password(user=self.owner, vault_id=self.vault.pk, **replacement(self.vault, byte=11))
        self.data["expected_entries_version"] = str(self.vault.entries_version)
        self.assertEqual(self.write("post", "key-rotation/", self.data).status_code, 409)

    def test_csrf_ownership_strict_fields_and_empty_vault(self):
        self.assertEqual(self.client.post(self.base + "key-rotation/", self.data, content_type="application/json").status_code, 403)
        self.assertEqual(self.write("post", "key-rotation/", {**self.data, "master_password": "synthetic"}).status_code, 400)
        other = get_user_model().objects.create_user(username="rotation-other")
        self.login(other)
        self.assertEqual(self.write("post", "key-rotation/", {}).status_code, 404)
        empty = make_vault(other)
        self.base = f"/api/vaults/{empty.pk}/"
        self.assertEqual(self.write("post", "key-rotation/", batch(empty, [])).status_code, 200)
        empty.refresh_from_db()
        self.assertEqual(empty.key_version, 2)


class ConcurrentKeyRotationTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_rotation_and_old_key_write_cannot_both_commit(self):
        user = get_user_model().objects.create_user(username="rotation-race")
        vault = make_vault(user)
        rotation = {**batch(vault, []), "expected_entries_version": vault.entries_version}
        item = envelope(2)
        gate = Barrier(2, timeout=10)

        def run(operation, **kwargs):
            try:
                gate.wait()
                operation(user=user, vault_id=vault.pk, **kwargs)
                return True
            except RevisionConflict:
                return False
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            rotated = pool.submit(run, rotate_key, **rotation)
            created = pool.submit(run, create_entry, entry_id=item["id"], nonce=item["nonce"], ciphertext=item["ciphertext"])
        self.assertNotEqual(rotated.result(), created.result())
        vault.refresh_from_db()
        self.assertEqual(vault.key_version, 2 if rotated.result() else 1)
        self.assertEqual(vault.entries.count(), int(created.result()))
