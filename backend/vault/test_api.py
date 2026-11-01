"""Transport tests use opaque synthetic ciphertext; authenticity is tested by clients."""
import base64
import json
import uuid
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from .models import NonceReservation, SecuritySettings, Vault, VaultEntry


FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "frontend/tests/fixtures/encryption-v1.json").read_text(encoding="utf-8"))


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class EncryptedVaultAPITests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="vault-owner")
        self.other = get_user_model().objects.create_user(username="vault-other")
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.owner, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        response = self.write("post", "/api/vaults/", FIXTURE["vault"])
        self.assertEqual(response.status_code, 201)
        self.vault = response.json()
        self.path = f"/api/vaults/{self.vault['id']}/entries/"

    def write(self, method, path, data):
        return getattr(self.client, method)(path, data, content_type="application/json", HTTP_X_CSRFTOKEN=self.token)

    def add(self, **overrides):
        data = {name: FIXTURE["entry"][name] for name in ("id", "nonce", "ciphertext")}
        return self.write("post", self.path, {**data, **overrides})

    def test_roundtrip_opaque_records_and_optimistic_revision_control(self):
        created = self.add()
        self.assertEqual(created.status_code, 201)
        row = created.json()
        detail = self.path + row["id"] + "/"
        self.assertEqual(self.client.get(detail).json()["ciphertext"], FIXTURE["entry"]["ciphertext"])
        self.assertEqual(self.client.get(self.path).json()["count"], 1)
        nonce = base64.b64encode(bytes([9]) * 12).decode()
        updated = self.write("patch", detail, {"nonce": nonce, "ciphertext": row["ciphertext"], "expected_revision": 1})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["revision"], 2)
        self.assertEqual(self.write("patch", detail, {"nonce": row["nonce"], "ciphertext": row["ciphertext"], "expected_revision": 1}).status_code, 409)
        self.assertEqual(self.write("delete", detail, {"expected_revision": 1}).status_code, 409)
        self.assertEqual(self.write("delete", detail, {"expected_revision": 2}).status_code, 204)
        self.assertEqual(self.client.get(self.path).json()["count"], 0)
        self.assertEqual(NonceReservation.objects.count(), 2)
        self.assertEqual(self.add().status_code, 409)

    def test_metadata_and_storage_never_contain_decrypted_entry_fields(self):
        self.add()
        metadata = self.client.get("/api/vaults/").json()["vaults"][0]
        self.assertNotIn("owner", metadata)
        self.assertNotIn("owner_id", metadata)
        stored = json.dumps(list(Vault.objects.values()), default=str) + json.dumps(list(VaultEntry.objects.values()), default=str)
        for secret in (FIXTURE["master"], FIXTURE["payload"]["password"], FIXTURE["payload"]["username"], FIXTURE["payload"]["notes"]):
            self.assertNotIn(secret, stored)
        for name in ("title", "username", "password", "website", "notes", "category", "favorite"):
            self.assertNotIn(name, self.client.get(self.path).json()["results"][0])

    def test_unknown_plaintext_fields_and_owner_injection_are_rejected(self):
        for name in ("password", "title", "notes", "owner", "master_password", "vault_id"):
            response = self.add(**{name: "plaintext must not be accepted"})
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("plaintext must not be accepted", response.content.decode())
        self.assertEqual(VaultEntry.objects.count(), 0)

    def test_anonymous_access_and_mutations_without_csrf_are_denied(self):
        self.assertEqual(Client().get("/api/vaults/").status_code, 403)
        response = self.client.post(self.path, {name: FIXTURE["entry"][name] for name in ("id", "nonce", "ciphertext")}, content_type="application/json")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(VaultEntry.objects.count(), 0)

    def test_other_accounts_cannot_list_retrieve_update_delete_or_create_in_a_vault(self):
        row = self.add().json()
        detail = self.path + row["id"] + "/"
        self.client.force_login(self.other, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]
        self.assertEqual(self.client.get("/api/vaults/").json(), {"vaults": []})
        self.assertEqual(self.client.get(self.path).status_code, 404)
        self.assertEqual(self.client.get(detail).status_code, 404)
        self.assertEqual(self.add().status_code, 404)
        self.assertEqual(self.write("patch", detail, {"nonce": row["nonce"], "ciphertext": row["ciphertext"], "expected_revision": 1}).status_code, 404)
        self.assertEqual(self.write("delete", detail, {"expected_revision": 1}).status_code, 404)
        self.assertEqual(VaultEntry.objects.get().revision, 1)

    def test_entry_must_belong_to_the_vault_in_its_route(self):
        row = self.add().json()
        second = self.write("post", "/api/vaults/", {**FIXTURE["vault"], "id": str(uuid.uuid4())}).json()
        self.assertEqual(self.client.get(f"/api/vaults/{second['id']}/entries/{row['id']}/").status_code, 404)

    def test_invalid_profiles_encoding_oversize_and_noncanonical_uuids_are_rejected(self):
        for name, value in (("kdf_memory_kib", 1024), ("kdf_iterations", 1), ("format_version", 2), ("kdf", "pbkdf2")):
            response = self.write("post", "/api/vaults/", {**FIXTURE["vault"], "id": str(uuid.uuid4()), name: value})
            self.assertEqual(response.status_code, 400)
        for changes in ({"nonce": "bad"}, {"ciphertext": "plaintext"}, {"id": uuid.uuid4().hex},
                        {"ciphertext": base64.b64encode(bytes(65553)).decode()}):
            self.assertEqual(self.add(**changes).status_code, 400)
        self.assertEqual(VaultEntry.objects.count(), 0)

    def test_expected_revision_requires_a_real_positive_integer(self):
        row = self.add().json()
        for value in (True, "1", 0, 1.5, None):
            self.assertEqual(self.write("delete", self.path + row["id"] + "/", {"expected_revision": value}).status_code, 400)
        self.assertEqual(VaultEntry.objects.count(), 1)

    def test_pagination_is_bounded_and_scoped(self):
        # Synthetic transport fixtures only; direct bulk inserts are never an API write path.
        VaultEntry.objects.bulk_create([VaultEntry(vault_id=self.vault["id"], nonce=base64.b64encode(index.to_bytes(12, "big")).decode(),
            ciphertext=FIXTURE["entry"]["ciphertext"]) for index in range(51)])
        page = self.client.get(self.path).json()
        self.assertEqual(page["count"], 51)
        self.assertEqual(len(page["results"]), 50)
        self.assertIsNotNone(page["next"])
        self.assertEqual(len(self.client.get(self.path + "?page=2").json()["results"]), 1)

    def test_security_settings_are_owned_bounded_and_strict(self):
        original = self.client.get("/api/security-settings/").json()
        self.assertEqual(original, {"auto_lock_seconds": 300, "lock_on_hidden": True})
        saved = self.write("patch", "/api/security-settings/", {"auto_lock_seconds": 60, "lock_on_hidden": False})
        self.assertEqual(saved.json(), {"auto_lock_seconds": 60, "lock_on_hidden": False})
        for changes in ({"auto_lock_seconds": 0}, {"auto_lock_seconds": True}, {"lock_on_hidden": "false"}, {"user": self.other.pk}):
            self.assertEqual(self.write("patch", "/api/security-settings/", changes).status_code, 400)
        self.assertFalse(SecuritySettings.objects.filter(user=self.other).exists())

    def test_sensitive_api_responses_are_not_cacheable(self):
        for path in ("/api/vaults/", self.path, "/api/security-settings/"):
            response = self.client.get(path)
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertIn("Cookie", response["Vary"])

    def test_streamed_json_has_a_hard_size_and_depth_bound(self):
        oversized = json.dumps({"ciphertext": "a" * (128 * 1024)})
        response = self.client.post(self.path, oversized, content_type="application/json", HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(response.status_code, 400)
        nested = '[' * 2000 + '0' + ']' * 2000
        response = self.client.post(self.path, nested, content_type="application/json", HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(VaultEntry.objects.count(), 0)
