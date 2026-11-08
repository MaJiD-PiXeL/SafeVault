import uuid

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from .services import create_entry, create_vault, delete_entry
from .test_master_password import encoded, replacement


class VaultRecoveryKeyTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="vault-recovery-owner")
        self.vault = create_vault(user=self.owner, vault_id=uuid.uuid4(), kdf_salt=encoded(16, 1),
                                  wrap_nonce=encoded(12, 1), wrapped_key=encoded(48, 1))
        self.client = Client(enforce_csrf_checks=True)
        self.path = f"/api/vaults/{self.vault.id}/"
        self.login(self.owner)
        self.recovery = {"nonce": encoded(12, 7), "wrapped_key": encoded(48, 7)}
        self.new_recovery = {"nonce": encoded(12, 8), "wrapped_key": encoded(48, 8)}

    def login(self, user):
        self.client.force_login(user, backend="django.contrib.auth.backends.ModelBackend")
        self.token = self.client.get("/api/auth/session/").json()["csrfToken"]

    def post(self, route, body):
        return self.client.post(self.path + route, body, content_type="application/json", HTTP_X_CSRFTOKEN=self.token)

    def setup_body(self, current, new):
        return {"expected_kdf_salt": self.vault.kdf_salt, "expected_wrap_nonce": self.vault.wrap_nonce,
                "expected_wrapped_key": self.vault.wrapped_key, "expected_key_version": self.vault.key_version,
                "expected_recovery": current, "recovery": new}

    def test_successful_reset_consumes_recovery_and_preserves_active_and_trashed_ciphertext(self):
        for byte in (2, 3):
            entry = create_entry(user=self.owner, vault_id=self.vault.pk, entry_id=uuid.uuid4(),
                                 nonce=encoded(12, byte), ciphertext=encoded(48, byte))
        delete_entry(user=self.owner, entry_id=entry.pk, expected_revision=1)
        self.vault.refresh_from_db()
        before = list(self.vault.entries.order_by("id").values())
        snapshot = self.vault.entries_version
        setup = self.post("recovery-key/", self.setup_body(None, self.recovery))
        self.assertEqual(setup.status_code, 200, setup.content)
        self.assertEqual(setup.json()["recovery"], self.recovery)
        self.assertEqual(setup["Cache-Control"], "no-store")
        data = {**replacement(self.vault), "expected_key_version": 1, "expected_recovery": self.recovery}
        result = self.post("recover/", data)
        self.assertEqual(result.status_code, 200, result.content)
        self.assertIsNone(result.json()["recovery"])
        self.assertEqual(result.json()["wrapped_key"], data["wrapped_key"])
        self.vault.refresh_from_db()
        self.assertEqual(self.vault.key_version, 1)
        self.assertEqual(self.vault.entries_version, snapshot)
        self.assertEqual(list(self.vault.entries.order_by("id").values()), before)
        replay = {**replacement(self.vault, byte=10), "expected_key_version": 1, "expected_recovery": self.recovery}
        self.assertEqual(self.post("recover/", replay).status_code, 409)

    def test_replacement_disable_and_key_rotation_reject_stale_recovery(self):
        self.assertEqual(self.post("recovery-key/", self.setup_body(None, self.recovery)).status_code, 200)
        self.assertEqual(self.post("recovery-key/", self.setup_body(self.recovery, self.new_recovery)).status_code, 200)
        recovery = {**replacement(self.vault), "expected_key_version": 1, "expected_recovery": self.recovery}
        self.assertEqual(self.post("recover/", recovery).status_code, 409)
        self.assertEqual(self.post("recovery-key/", self.setup_body(self.recovery, None)).status_code, 409)
        self.assertEqual(self.post("recovery-key/", self.setup_body(self.new_recovery, None)).status_code, 200)
        self.assertEqual(self.post("recovery-key/", self.setup_body(None, self.recovery)).status_code, 200)
        rotate = {**replacement(self.vault), "expected_key_version": 1, "expected_entries_version": str(self.vault.entries_version), "entries": []}
        result = self.post("key-rotation/", rotate)
        self.assertEqual(result.status_code, 200, result.content)
        self.assertIsNone(result.json()["recovery"])
        self.assertEqual(self.post("recover/", recovery).json()["code"], "vault_key_changed")

    def test_master_change_preserves_recovery_but_invalidates_stale_setup(self):
        data = self.setup_body(None, self.recovery)
        self.assertEqual(self.post("recovery-key/", data).status_code, 200)
        changed = self.post("master-password/", replacement(self.vault))
        self.assertEqual(changed.status_code, 200, changed.content)
        self.assertEqual(changed.json()["recovery"], self.recovery)
        self.assertEqual(self.post("recovery-key/", self.setup_body(self.recovery, self.new_recovery)).status_code, 409)

    def test_ownership_csrf_and_strict_ciphertext_only_schema(self):
        data = self.setup_body(None, self.recovery)
        self.assertEqual(self.client.post(self.path + "recovery-key/", data, content_type="application/json").status_code, 403)
        self.assertEqual(self.post("recovery-key/", {**data, "recovery_code": "synthetic"}).status_code, 400)
        self.assertEqual(self.post("recovery-key/", {**data, "recovery": {**self.recovery, "nonce": "bad"}}).status_code, 400)
        self.login(get_user_model().objects.create_user(username="recovery-other"))
        self.assertEqual(self.post("recovery-key/", data).status_code, 404)
        self.assertEqual(self.post("recover/", {}).status_code, 404)
