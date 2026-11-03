# Test data represents opaque transport bytes, not an encryption implementation.
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, connections, transaction
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from .models import NonceReservation, SecuritySettings, Vault, VaultEntry
from .services import RevisionConflict, create_entry, create_vault, delete_entry, list_entries, purge_entry, update_entry
from .validators import Base64Bytes


@override_settings(DEBUG=False, ALLOWED_HOSTS=["localhost", "127.0.0.1", "testserver"])
class PublicEndpointTests(SimpleTestCase):
    def test_endpoints_return_json_without_database_access(self):
        for name in ("root", "vault:home", "vault:health"):
            with self.subTest(name=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.status_code, 200)
                self.assertIn("status", response.json())

    def test_localhost_works_with_debug_disabled(self):
        response = self.client.get("/api/health/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(response.json(), {"status": "healthy"})

    def test_endpoints_reject_mutations(self):
        for path in ("/", "/api/", "/api/health/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path).status_code, 405)

    def test_unknown_host_is_rejected(self):
        response = self.client.get("/api/health/", HTTP_HOST="untrusted.example")
        self.assertEqual(response.status_code, 400)

    def test_frontend_origin_receives_cors_headers(self):
        response = self.client.get("/api/health/", HTTP_ORIGIN="http://localhost:5173")
        self.assertEqual(response["Access-Control-Allow-Origin"], "http://localhost:5173")

    def test_untrusted_origin_receives_no_cors_permission(self):
        response = self.client.get("/api/health/", HTTP_ORIGIN="https://untrusted.example")
        self.assertNotIn("Access-Control-Allow-Origin", response)


def encoded(size, byte=1):
    return base64.b64encode(bytes([byte]) * size).decode("ascii")


class EnvelopeValidationTests(SimpleTestCase):
    def test_rejects_plaintext_and_malformed_or_noncanonical_base64(self):
        for value in ("secret", "🔐", "", "!!!!", "Zg==\n", "Zh==", None, 123):
            with self.subTest(value=value), self.assertRaises(ValidationError) as error:
                Base64Bytes(1, 64)(value)
            self.assertEqual(error.exception.messages, ["Invalid encoded data."])

    def test_requires_exact_nonce_length_and_bounded_payload(self):
        Base64Bytes(12, 12)(encoded(12))
        Base64Bytes(17, 65552)(encoded(65552))
        for size in (0, 11, 13):
            with self.subTest(size=size), self.assertRaises(ValidationError):
                Base64Bytes(12, 12)(encoded(size))
        with self.assertRaises(ValidationError):
            Base64Bytes(17, 65552)(encoded(65553))

    def test_new_drf_views_require_authentication_by_default(self):
        class PrivateView(APIView):
            def get(self, request):
                return Response({"status": "private"})

        response = PrivateView.as_view()(APIRequestFactory().get("/private/"))
        self.assertEqual(response.status_code, 403)


class VaultStorageTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = get_user_model().objects.create_user(username="owner")
        cls.other = get_user_model().objects.create_user(username="other")
        cls.vault = Vault.objects.create(
            owner=cls.owner, kdf_salt=encoded(16), wrap_nonce=encoded(12), wrapped_key=encoded(48),
        )

    def create(self, *, byte=2, **overrides):
        values = dict(user=self.owner, vault_id=self.vault.pk, entry_id=uuid.uuid4(),
                      nonce=encoded(12, byte), ciphertext=encoded(50, byte))
        values.update(overrides)
        return create_entry(**values)

    def test_entry_stores_only_opaque_data_and_supports_owner_listing(self):
        entry = self.create()
        stored = VaultEntry.objects.get(pk=entry.pk)
        self.assertEqual(stored.ciphertext, encoded(50, 2))
        self.assertEqual(stored.revision, 1)
        self.assertEqual(list(list_entries(user=self.owner, vault_id=self.vault.pk)), [entry])
        fields = {field.name for field in VaultEntry._meta.fields}
        self.assertTrue(fields.isdisjoint({"password", "title", "username", "website", "notes", "category", "favorite"}))
        self.assertEqual(NonceReservation.objects.filter(vault=self.vault).count(), 1)

    def test_provisioning_sets_owner_and_creates_security_settings(self):
        vault = create_vault(user=self.other, vault_id=uuid.uuid4(), kdf_salt=encoded(16, 4),
                             wrap_nonce=encoded(12, 4), wrapped_key=encoded(48, 4))
        self.assertEqual(vault.owner, self.other)
        self.assertTrue(SecuritySettings.objects.filter(user=self.other).exists())
        with self.assertRaises(PermissionDenied):
            create_vault(user=AnonymousUser(), vault_id=uuid.uuid4(), kdf_salt=encoded(16),
                         wrap_nonce=encoded(12), wrapped_key=encoded(48))

    def test_other_user_cannot_list_create_update_or_delete(self):
        entry = self.create()
        with self.assertRaises(Vault.DoesNotExist):
            list_entries(user=self.other, vault_id=self.vault.pk)
        with self.assertRaises(Vault.DoesNotExist):
            self.create(user=self.other, byte=3)
        with self.assertRaises(VaultEntry.DoesNotExist):
            update_entry(user=self.other, entry_id=entry.pk, expected_revision=1,
                         nonce=encoded(12, 3), ciphertext=encoded(50))
        with self.assertRaises(VaultEntry.DoesNotExist):
            delete_entry(user=self.other, entry_id=entry.pk, expected_revision=1)
        self.assertTrue(VaultEntry.objects.filter(pk=entry.pk).exists())

    def test_anonymous_and_inactive_users_are_denied(self):
        self.other.is_active = False
        for user in (None, AnonymousUser(), self.other):
            with self.subTest(user=user), self.assertRaises(PermissionDenied):
                self.create(user=user)
            self.assertFalse(Vault.objects.for_user(user).exists())
            self.assertFalse(VaultEntry.objects.for_user(user).exists())

    def test_nonce_cannot_be_reused_after_update_or_delete(self):
        entry = self.create()
        updated = update_entry(user=self.owner, entry_id=entry.pk, expected_revision=1,
                               nonce=encoded(12, 3), ciphertext=encoded(60))
        self.assertEqual(updated.revision, 2)
        with self.assertRaises(ValidationError):
            update_entry(user=self.owner, entry_id=entry.pk, expected_revision=2,
                         nonce=encoded(12, 2), ciphertext=encoded(60))
        delete_entry(user=self.owner, entry_id=entry.pk, expected_revision=2)
        self.assertTrue(VaultEntry.objects.filter(pk=entry.pk, deleted_at__isnull=False).exists())
        purge_entry(user=self.owner, entry_id=entry.pk, expected_revision=2, expected_state_version=2)
        self.assertFalse(VaultEntry.objects.filter(pk=entry.pk).exists())
        for byte in (2, 3):
            with self.subTest(byte=byte), self.assertRaises(ValidationError):
                self.create(byte=byte)
        self.assertEqual(NonceReservation.objects.filter(vault=self.vault).count(), 2)

    def test_same_nonce_in_different_vaults_is_allowed(self):
        self.create()
        second = Vault.objects.create(owner=self.owner, kdf_salt=encoded(16, 3),
                                      wrap_nonce=encoded(12, 3), wrapped_key=encoded(48, 3))
        self.create(vault_id=second.pk)
        self.assertEqual(VaultEntry.objects.count(), 2)

    def test_stale_revision_cannot_overwrite_or_delete_newer_data(self):
        entry = self.create()
        update_entry(user=self.owner, entry_id=entry.pk, expected_revision=1,
                     nonce=encoded(12, 3), ciphertext=encoded(60))
        for revision in (1, True, "2"):
            with self.subTest(revision=revision), self.assertRaises(RevisionConflict):
                update_entry(user=self.owner, entry_id=entry.pk, expected_revision=revision,
                             nonce=encoded(12, 4), ciphertext=encoded(70))
        with self.assertRaises(RevisionConflict):
            delete_entry(user=self.owner, entry_id=entry.pk, expected_revision=1)
        self.assertFalse(NonceReservation.objects.filter(nonce=encoded(12, 4)).exists())
        entry.refresh_from_db()
        self.assertEqual(entry.ciphertext, encoded(60))

    def test_failed_create_leaves_no_entry_or_nonce_reservation(self):
        with self.assertRaises(ValidationError):
            self.create(ciphertext="plaintext must never be accepted")
        self.assertEqual(VaultEntry.objects.count(), 0)
        self.assertEqual(NonceReservation.objects.count(), 0)

    def test_failed_update_keeps_existing_ciphertext_and_revision(self):
        entry = self.create()
        with self.assertRaises(ValidationError):
            update_entry(user=self.owner, entry_id=entry.pk, expected_revision=1,
                         nonce=encoded(12, 3), ciphertext="invalid")
        entry.refresh_from_db()
        self.assertEqual(entry.revision, 1)
        self.assertEqual(entry.ciphertext, encoded(50, 2))
        self.assertEqual(NonceReservation.objects.count(), 1)

    def test_database_constraints_reject_bypassing_model_validation(self):
        entry = self.create()
        for changes in ({"revision": 0}, {"ciphertext": ""}):
            with self.subTest(changes=changes), self.assertRaises(IntegrityError), transaction.atomic():
                VaultEntry.objects.filter(pk=entry.pk).update(**changes)
        with self.assertRaises(IntegrityError), transaction.atomic():
            NonceReservation.objects.bulk_create([NonceReservation(vault=self.vault, nonce=entry.nonce)])
        with self.assertRaises(IntegrityError), transaction.atomic():
            Vault.objects.filter(pk=self.vault.pk).update(kdf_memory_kib=1024)

    def test_unsupported_crypto_or_malformed_wrapped_key_is_rejected(self):
        for changes in ({"format_version": 2}, {"kdf_iterations": 1}, {"kdf_version": 16},
                        {"kdf_salt": encoded(8)}, {"wrapped_key": encoded(32)}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                Vault.objects.create(owner=self.owner, **{
                    "kdf_salt": encoded(16), "wrap_nonce": encoded(12),
                    "wrapped_key": encoded(48), **changes,
                })

    def test_security_settings_are_one_per_user_with_bounded_auto_lock(self):
        settings = SecuritySettings.objects.create(user=self.owner)
        self.assertEqual(settings.auto_lock_seconds, 300)
        self.assertTrue(settings.lock_on_hidden)
        with self.assertRaises(ValidationError):
            SecuritySettings.objects.create(user=self.owner)
        for timeout in (0, 59, 3601):
            settings.auto_lock_seconds = timeout
            with self.subTest(timeout=timeout), self.assertRaises(ValidationError):
                settings.save()

    def test_model_representations_do_not_include_envelope_data(self):
        entry = self.create()
        self.assertNotIn(entry.ciphertext, repr(entry))
        self.assertNotIn(self.vault.wrapped_key, repr(self.vault))


class ConcurrentVaultWriteTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_only_one_concurrent_update_can_commit_for_the_same_revision(self):
        user = get_user_model().objects.create_user(username="concurrent-owner")
        vault = create_vault(user=user, vault_id=uuid.uuid4(), kdf_salt=encoded(16),
                             wrap_nonce=encoded(12), wrapped_key=encoded(48))
        entry = create_entry(user=user, vault_id=vault.pk, entry_id=uuid.uuid4(),
                             nonce=encoded(12, 2), ciphertext=encoded(50))
        barrier = Barrier(2)

        def attempt(byte):
            try:
                thread_user = get_user_model().objects.get(pk=user.pk)
                barrier.wait(timeout=10)
                try:
                    update_entry(user=thread_user, entry_id=entry.pk, expected_revision=1,
                                 nonce=encoded(12, byte), ciphertext=encoded(50, byte))
                    return "updated"
                except RevisionConflict:
                    return "conflict"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, (3, 4)))
        self.assertCountEqual(results, ["updated", "conflict"])
        entry.refresh_from_db()
        self.assertEqual(entry.revision, 2)
        self.assertEqual(NonceReservation.objects.filter(vault=vault).count(), 2)
