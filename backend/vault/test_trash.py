"""Trash lifecycle tests use opaque synthetic ciphertext, never a real vault."""
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection, connections
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone

from .models import NonceReservation, RestoreReceipt, VaultEntry
from .services import (RevisionConflict, create_entry, create_vault, delete_entry,
                       purge_entry, restore_entry)


def encoded(length, byte=1):
    return base64.b64encode(bytes([byte]) * length).decode()


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class TrashAPITests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="trash-owner")
        self.other = get_user_model().objects.create_user(username="trash-other")
        self.vault = create_vault(user=self.owner, vault_id=uuid.uuid4(), kdf_salt=encoded(16), wrap_nonce=encoded(12), wrapped_key=encoded(48))
        self.entry = create_entry(user=self.owner, vault_id=self.vault.pk, entry_id=uuid.uuid4(), nonce=encoded(12, 2), ciphertext=encoded(48, 2))
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.owner, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        self.path = f"/api/vaults/{self.vault.pk}/entries/"
        self.detail = self.path + str(self.entry.pk) + "/"
        self.versions = {"expected_revision": 1, "expected_state_version": 1}

    def write(self, method, path=None, data=None):
        return getattr(self.client, method)(path or self.detail, self.versions if data is None else data,
                                           content_type="application/json", HTTP_X_CSRFTOKEN=self.token)

    def test_move_restore_preserves_ciphertext_identity_and_aad_revision(self):
        original = self.client.get(self.detail).json()
        removed = self.write("delete")
        self.assertEqual(removed.status_code, 200)
        trashed = removed.json()
        self.assertEqual(trashed["state_version"], 2)
        self.assertIsNotNone(trashed["deleted_at"])
        self.assertEqual(self.client.get(self.path).json()["count"], 0)
        self.assertEqual(self.client.get(self.path + "?state=trash").json()["count"], 1)
        self.assertEqual(self.client.get(self.path + "?state=all").json()["count"], 1)
        restored = self.write("post", self.detail + "restore/", {**self.versions, "expected_state_version": 2})
        self.assertEqual(restored.status_code, 200)
        active = restored.json()
        self.assertEqual(active["state_version"], 3)
        self.assertIsNone(active["deleted_at"])
        for name in ("id", "vault_id", "nonce", "ciphertext", "revision", "created_at"):
            self.assertEqual(original[name], trashed[name])
            self.assertEqual(original[name], active[name])
        self.assertEqual(self.client.get(self.path).json()["count"], 1)
        self.assertEqual(self.client.get(self.path + "?state=trash").json()["count"], 0)
        self.assertEqual(NonceReservation.objects.count(), 1)

    def test_stale_edit_delete_restore_and_purge_are_rejected_across_state_cycles(self):
        self.write("delete")
        fresh = {**self.versions, "expected_state_version": 2}
        self.assertEqual(self.write("patch", data={**fresh, "nonce": encoded(12, 3), "ciphertext": encoded(48, 3)}).status_code, 409)
        self.assertEqual(self.write("delete", data=fresh).status_code, 409)
        self.assertEqual(self.write("post", self.detail + "restore/", self.versions).status_code, 409)
        self.assertEqual(self.write("delete", self.detail + "purge/", self.versions).status_code, 409)
        self.assertEqual(self.write("post", self.detail + "restore/", fresh).status_code, 200)
        self.assertEqual(self.write("patch", data={**self.versions, "nonce": encoded(12, 3), "ciphertext": encoded(48, 3)}).status_code, 409)
        self.assertEqual(self.write("delete").status_code, 409)
        self.assertEqual(self.write("post", self.detail + "restore/", {**fresh, "expected_state_version": 3}).status_code, 409)
        updated = self.write("patch", data={"expected_revision": 1, "expected_state_version": 3, "nonce": encoded(12, 3), "ciphertext": encoded(48, 3)})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["revision"], 2)
        self.assertEqual(updated.json()["state_version"], 3)

    def test_only_trash_can_be_purged_and_nonce_and_restore_receipt_survive(self):
        receipt = RestoreReceipt.objects.create(vault=self.vault, backup_id=uuid.uuid4(), archive_digest="a" * 64, entry_count=1)
        self.assertEqual(self.write("delete", self.detail + "purge/").status_code, 409)
        self.write("delete")
        self.assertEqual(self.write("delete", self.detail + "purge/", {**self.versions, "expected_state_version": 2}).status_code, 204)
        self.assertFalse(VaultEntry.objects.filter(pk=self.entry.pk).exists())
        self.assertTrue(NonceReservation.objects.filter(vault=self.vault, nonce=self.entry.nonce).exists())
        self.assertTrue(RestoreReceipt.objects.filter(pk=receipt.pk).exists())
        self.assertEqual(self.client.get(self.detail).status_code, 404)
        self.assertEqual(self.write("post", self.detail + "restore/", {**self.versions, "expected_state_version": 2}).status_code, 404)
        retry = self.write("post", self.path, {"id": str(uuid.uuid4()), "nonce": self.entry.nonce, "ciphertext": self.entry.ciphertext})
        self.assertEqual(retry.status_code, 409)

    def test_missing_malformed_and_injected_lifecycle_fields_are_rejected(self):
        for data in [{}, {"expected_revision": 1}, {"expected_state_version": 1},
                     *({**self.versions, "expected_state_version": value} for value in [True, "1", 0, -1, 1.5, None, 2147483648]),
                     {**self.versions, "deleted_at": None}, {**self.versions, "state_version": 3}, {**self.versions, "password": "do not accept"}]:
            with self.subTest(data=data):
                self.assertEqual(self.write("delete", data=data).status_code, 400)
        self.entry.refresh_from_db()
        self.assertIsNone(self.entry.deleted_at)
        self.assertEqual(self.entry.state_version, 1)

    def test_trash_respects_ownership_vault_scope_csrf_and_no_store(self):
        self.write("delete")
        restore_path = self.detail + "restore/"
        purge_path = self.detail + "purge/"
        for path in [self.path + "?state=trash", self.path + "?state=all", self.detail]:
            response = self.client.get(path)
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertIn("Cookie", response["Vary"])
            self.assertEqual(Client().get(path).status_code, 403)
        self.assertEqual(self.client.post(restore_path, {**self.versions, "expected_state_version": 2}, content_type="application/json").status_code, 403)
        self.assertEqual(self.client.delete(purge_path, {**self.versions, "expected_state_version": 2}, content_type="application/json").status_code, 403)
        other_vault = create_vault(user=self.owner, vault_id=uuid.uuid4(), kdf_salt=encoded(16, 4), wrap_nonce=encoded(12, 4), wrapped_key=encoded(48, 4))
        wrong_route = restore_path.replace(str(self.vault.pk), str(other_vault.pk))
        self.assertEqual(self.write("post", wrong_route).status_code, 404)
        self.client.force_login(self.other, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        for path in [self.path + "?state=trash", self.path + "?state=all", self.detail]:
            self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(self.write("post", restore_path, {}).status_code, 404)
        self.assertEqual(self.write("delete", purge_path, {}).status_code, 404)
        self.assertTrue(VaultEntry.objects.filter(pk=self.entry.pk).exists())

    def test_invalid_list_states_are_rejected(self):
        for value in ["deleted", "ALL", "", "plaintext"]:
            self.assertEqual(self.client.get(self.path + "?state=" + value).status_code, 400)

    def test_combined_pagination_includes_both_active_and_trashed_rows(self):
        VaultEntry.objects.bulk_create([
            VaultEntry(vault=self.vault, nonce=base64.b64encode(index.to_bytes(12, "big")).decode(),
                       ciphertext=encoded(48), deleted_at=timezone.now() if index % 2 else None,
                       state_version=2 if index % 2 else 1)
            for index in range(50)
        ])
        self.assertEqual(self.client.get(self.path).json()["count"], 26)
        self.assertEqual(self.client.get(self.path + "?state=trash").json()["count"], 25)
        first = self.client.get(self.path + "?state=all&page=1").json()
        second = self.client.get(self.path + "?state=all&page=2").json()
        self.assertEqual(first["count"], 51)
        self.assertEqual(len(first["results"]), 50)
        self.assertEqual(len(second["results"]), 1)
        self.assertEqual(len({row["id"] for row in first["results"] + second["results"]}), 51)

    def test_trash_counts_toward_capacity_and_purge_frees_capacity(self):
        with patch("vault.services.MAX_VAULT_ENTRIES", 1):
            self.write("delete")
            data = {"id": str(uuid.uuid4()), "nonce": encoded(12, 3), "ciphertext": encoded(48, 3)}
            self.assertEqual(self.write("post", self.path, data).status_code, 400)
            self.assertEqual(self.write("post", self.detail + "restore/", {**self.versions, "expected_state_version": 2}).status_code, 200)
            self.assertEqual(self.write("delete", data={**self.versions, "expected_state_version": 3}).status_code, 200)
            self.assertEqual(self.write("delete", self.detail + "purge/", {**self.versions, "expected_state_version": 4}).status_code, 204)
            self.assertEqual(self.write("post", self.path, data).status_code, 201)
        self.assertEqual(NonceReservation.objects.count(), 2)

    def test_state_version_never_wraps_or_silently_reuses_an_old_value(self):
        VaultEntry.objects.filter(pk=self.entry.pk).update(state_version=2147483647)
        self.assertEqual(self.write("delete", data={**self.versions, "expected_state_version": 2147483647}).status_code, 409)
        self.entry.refresh_from_db()
        self.assertIsNone(self.entry.deleted_at)
        self.assertEqual(self.entry.state_version, 2147483647)


class ConcurrentTrashTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_restore_and_purge_cannot_both_commit_the_same_version(self):
        owner = get_user_model().objects.create_user(username="trash-race")
        vault = create_vault(user=owner, vault_id=uuid.uuid4(), kdf_salt=encoded(16), wrap_nonce=encoded(12), wrapped_key=encoded(48))
        entry = create_entry(user=owner, vault_id=vault.pk, entry_id=uuid.uuid4(), nonce=encoded(12, 2), ciphertext=encoded(48, 2))
        delete_entry(user=owner, entry_id=entry.pk, expected_revision=1)
        barrier = Barrier(2)

        def attempt(operation):
            try:
                user = get_user_model().objects.get(pk=owner.pk)
                barrier.wait(timeout=10)
                try:
                    operation(user=user, entry_id=entry.pk, expected_revision=1, expected_state_version=2)
                    return "committed"
                except (RevisionConflict, VaultEntry.DoesNotExist):
                    return "conflict"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(attempt, [restore_entry, purge_entry])), ["committed", "conflict"])
        self.assertEqual(NonceReservation.objects.filter(vault=vault).count(), 1)


class TrashMigrationTests(TransactionTestCase):
    def test_existing_envelopes_and_restore_history_survive_migration(self):
        before = [("vault", "0002_restorereceipt")]
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        # Always restore the schema, including when a preservation assertion fails.
        self.addCleanup(lambda: MigrationExecutor(connection).migrate(latest))
        executor.migrate(before)
        old_apps = executor.loader.project_state(before).apps
        owner = old_apps.get_model("auth", "User").objects.create(username="migration-owner")
        vault = old_apps.get_model("vault", "Vault").objects.create(
            owner_id=owner.pk, kdf_salt=encoded(16), wrap_nonce=encoded(12), wrapped_key=encoded(48))
        entry = old_apps.get_model("vault", "VaultEntry").objects.create(
            vault_id=vault.pk, nonce=encoded(12, 2), ciphertext=encoded(48, 3), revision=7)
        nonce = old_apps.get_model("vault", "NonceReservation").objects.create(vault_id=vault.pk, nonce=entry.nonce)
        receipt = old_apps.get_model("vault", "RestoreReceipt").objects.create(
            vault_id=vault.pk, backup_id=uuid.uuid4(), archive_digest="a" * 64, entry_count=1)

        MigrationExecutor(connection).migrate(latest)

        migrated = VaultEntry.objects.get(pk=entry.pk)
        self.assertIsNone(migrated.deleted_at)
        self.assertEqual(migrated.state_version, 1)
        for name in ("vault_id", "nonce", "ciphertext", "revision", "created_at", "updated_at"):
            self.assertEqual(getattr(migrated, name), getattr(entry, name), name)
        current_vault = migrated.vault
        for name in ("kdf_salt", "wrap_nonce", "wrapped_key", "created_at", "updated_at"):
            self.assertEqual(getattr(current_vault, name), getattr(vault, name), name)
        self.assertTrue(NonceReservation.objects.filter(pk=nonce.pk, vault_id=vault.pk, nonce=entry.nonce).exists())
        self.assertTrue(RestoreReceipt.objects.filter(
            pk=receipt.pk, vault_id=vault.pk, backup_id=receipt.backup_id,
            archive_digest=receipt.archive_digest, entry_count=1).exists())
