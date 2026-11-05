import base64
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from .api_views import EntryPagination
from .models import Vault
from .services import create_entry, create_vault, delete_entry, purge_entry, restore_entries, restore_entry, update_entry


def opaque(size, byte):
    return base64.b64encode(bytes([byte]) * size).decode()


class EntrySyncTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="sync-owner")
        self.vault = create_vault(user=self.owner, vault_id=uuid.uuid4(), kdf_salt=opaque(16, 1),
                                  wrap_nonce=opaque(12, 1), wrapped_key=opaque(48, 1))
        self.path = f"/api/vaults/{self.vault.pk}"
        self.client.force_login(self.owner, backend="django.contrib.auth.backends.ModelBackend")

    def version(self):
        response = self.client.get(self.path + "/entries-version/")
        self.assertIn("no-store", response["Cache-Control"])
        version = response.json()["version"]
        self.assertEqual(self.client.get(self.path + "/entries/?state=all&page=1").json()["version"], version)
        return version

    def create(self):
        return create_entry(user=self.owner, vault_id=self.vault.pk, entry_id=uuid.uuid4(),
                            nonce=opaque(12, 2), ciphertext=opaque(48, 2))

    def test_every_entry_mutation_invalidates_snapshot_and_repeated_restore_is_stable(self):
        seen = [self.version()]
        entry = self.create()
        seen.append(self.version())
        update_entry(user=self.owner, entry_id=entry.pk, expected_revision=1, nonce=opaque(12, 3),
                     ciphertext=opaque(48, 3), expected_state_version=1)
        seen.append(self.version())
        delete_entry(user=self.owner, entry_id=entry.pk, expected_revision=2, expected_state_version=1)
        seen.append(self.version())
        restore_entry(user=self.owner, entry_id=entry.pk, expected_revision=2, expected_state_version=2)
        seen.append(self.version())
        delete_entry(user=self.owner, entry_id=entry.pk, expected_revision=2, expected_state_version=3)
        seen.append(self.version())
        purge_entry(user=self.owner, entry_id=entry.pk, expected_revision=2, expected_state_version=4)
        seen.append(self.version())
        backup = dict(user=self.owner, vault_id=self.vault.pk, backup_id=uuid.uuid4(), archive_digest="a" * 64,
                      entries=[{"id": uuid.uuid4(), "nonce": opaque(12, 4), "ciphertext": opaque(48, 4)}])
        restore_entries(**backup)
        seen.append(self.version())
        restore_entries(**backup)
        self.assertEqual(self.version(), seen[-1])
        self.assertEqual(len(set(seen)), len(seen))
        self.client.force_login(get_user_model().objects.create_user(username="sync-other"),
                                backend="django.contrib.auth.backends.ModelBackend")
        self.assertEqual(self.client.get(self.path + "/entries-version/").status_code, 404)

    def test_mutation_during_page_read_does_not_return_a_mixed_snapshot(self):
        original = EntryPagination.paginate_queryset

        def change_version(paginator, *args, **kwargs):
            page = original(paginator, *args, **kwargs)
            Vault.objects.filter(pk=self.vault.pk).update(entries_version=uuid.uuid4())
            return page

        with patch.object(EntryPagination, "paginate_queryset", change_version):
            response = self.client.get(self.path + "/entries/?state=all&page=1")
        self.assertEqual(response.status_code, 409)
