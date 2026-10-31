import hashlib
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import database
import main
from security import decrypt_password, encrypt_password, generate_key, generate_key_from_password, hash_password, verify_password


class VaultFlowTests(unittest.TestCase):
    def setUp(self):
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value
        self.output = io.StringIO()
        self.addCleanup(patch.stopall)
        patch("database.connect_db", return_value=self.connection).start()
        patch("main.connect_db", return_value=self.connection).start()
        self.inputs = patch("builtins.input").start()
        self.secret_input = patch("main.getpass").start()
        self.stdout = redirect_stdout(self.output)
        self.stdout.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)

    def test_setup_returns_key_and_stores_salted_verifier(self):
        self.cursor.fetchone.return_value = None
        self.secret_input.side_effect = [" master ", " master "]
        key = main.setup_master_password()
        _, values = self.cursor.execute.call_args.args
        stored, salt_hex = values
        salt = bytes.fromhex(salt_hex)
        self.assertTrue(verify_password(" master ", stored, salt))
        self.assertEqual(key, generate_key_from_password(" master ", salt))
        self.assertNotEqual(stored, hashlib.sha256(b" master ").hexdigest())
        self.connection.commit.assert_called_once()
        self.connection.close.assert_called_once()

    def test_setup_rejects_empty_or_mismatched_passwords(self):
        self.cursor.fetchone.return_value = None
        for values in (["", ""], ["one", "two"]):
            self.secret_input.side_effect = values
            self.assertIsNone(main.setup_master_password())
        self.connection.commit.assert_not_called()

    def test_setup_existing_vault_does_not_prompt(self):
        self.cursor.fetchone.return_value = ("existing",)
        self.assertIsNone(main.setup_master_password())
        self.secret_input.assert_not_called()

    def test_login_upgrades_legacy_hash_without_changing_encryption_key(self):
        salt = bytes(range(16))
        self.cursor.fetchone.return_value = (1, hashlib.sha256(b"legacy").hexdigest(), salt.hex())
        self.secret_input.return_value = "legacy"
        key = main.login()
        self.assertEqual(key, generate_key_from_password("legacy", salt))
        query, values = self.cursor.execute.call_args.args
        self.assertIn("UPDATE vault", query)
        self.assertEqual(values[0], hash_password("legacy", salt))
        self.connection.commit.assert_called_once()

    def test_wrong_login_does_not_update_hash(self):
        salt = bytes(range(16))
        self.cursor.fetchone.return_value = (1, hash_password("correct", salt), salt.hex())
        self.secret_input.return_value = "wrong"
        self.assertIsNone(main.login())
        self.connection.commit.assert_not_called()

    def test_login_with_current_hash_does_not_write(self):
        salt = bytes(range(16))
        self.cursor.fetchone.return_value = (1, hash_password("correct", salt), salt.hex())
        self.secret_input.return_value = "correct"
        self.assertEqual(main.login(), generate_key_from_password("correct", salt))
        self.connection.commit.assert_not_called()

    def test_add_preserves_password_spaces_and_encrypts(self):
        self.inputs.side_effect = ["Example", "user", "example.com", "notes"]
        self.secret_input.return_value = "  secret  "
        key = generate_key()
        main.add_password(key)
        _, values = self.cursor.execute.call_args.args
        self.assertEqual(decrypt_password(values[2], key), "  secret  ")
        self.connection.commit.assert_called_once()
        self.connection.close.assert_called_once()

    def test_edit_password_stores_ciphertext(self):
        self.cursor.fetchone.return_value = {"id": 1, "title": "Example"}
        self.inputs.side_effect = ["1", "3", "6"]
        self.secret_input.return_value = "  new secret  "
        key = generate_key()
        main.edit_password(key)
        query, values = self.cursor.execute.call_args.args
        self.assertIn("UPDATE passwords SET encrypted_password", query)
        self.assertEqual(decrypt_password(values[0], key), "  new secret  ")
        self.connection.commit.assert_called_once()

    def test_edit_connection_failure_is_handled(self):
        with patch("main.connect_db", side_effect=RuntimeError("connection unavailable")):
            main.edit_password(generate_key())
        self.assertIn("connection unavailable", self.output.getvalue())

    def test_reveal_existing_password(self):
        key = generate_key()
        self.inputs.return_value = "1"
        self.cursor.fetchone.return_value = ("Example", encrypt_password("secret", key))
        main.reveal_password(key)
        self.assertIn("Password: secret", self.output.getvalue())
        self.connection.close.assert_called_once()

    def test_reveal_missing_account_returns_without_decryption(self):
        self.inputs.return_value = "1"
        self.cursor.fetchone.return_value = None
        with patch("main.decrypt_password") as decrypt:
            main.reveal_password(generate_key())
        decrypt.assert_not_called()
        self.assertNotIn("Password:", self.output.getvalue())

    def test_reveal_corrupted_password_explains_recovery(self):
        self.inputs.return_value = "1"
        self.cursor.fetchone.return_value = ("Example", "old plaintext from edit bug")
        main.reveal_password(generate_key())
        self.assertNotIn("old plaintext", self.output.getvalue())
        self.assertNotIn("Password:", self.output.getvalue())
        self.assertIn("دوباره ویرایش", self.output.getvalue())
        self.connection.close.assert_called_once()

    def test_invalid_delete_id_does_not_query_or_delete(self):
        self.cursor.fetchall.return_value = [{"id": 1, "title": "Example", "username": None, "website": None, "notes": None}]
        self.inputs.return_value = "invalid"
        main.delete_password()
        self.assertEqual(self.cursor.execute.call_count, 1)
        self.connection.commit.assert_not_called()
        self.assertNotIn("An error occurred", self.output.getvalue())

    def test_delete_requires_explicit_confirmation(self):
        self.cursor.fetchall.return_value = [{"id": 1, "title": "Example", "username": None, "website": None, "notes": None}]
        self.cursor.fetchone.return_value = {"id": 1, "title": "Example"}
        self.inputs.side_effect = ["1", "no"]
        main.delete_password()
        self.connection.commit.assert_not_called()

    def test_confirmed_delete_uses_selected_id(self):
        self.cursor.fetchall.return_value = [{"id": 1, "title": "Example", "username": None, "website": None, "notes": None}]
        self.cursor.fetchone.return_value = {"id": 1, "title": "Example"}
        self.inputs.side_effect = ["1", "DELETE"]
        main.delete_password()
        self.cursor.execute.assert_called_with("DELETE FROM passwords WHERE id = %s", (1,))
        self.connection.commit.assert_called_once()

    def test_search_displays_website_instead_of_username(self):
        self.inputs.return_value = "example"
        self.cursor.fetchall.return_value = [{"id": 1, "title": "Example", "username": "user", "website": "example.com", "notes": None}]
        main.search_password()
        self.assertIn("Website: example.com", self.output.getvalue())
        self.assertEqual(self.cursor.execute.call_args.args[1], ("%example%",) * 3)

    def test_startup_authenticates_only_once(self):
        self.inputs.return_value = "8"
        with patch("main.create_tables"), patch("main.setup_master_password", return_value=None) as setup, patch("main.login", return_value=generate_key()) as login:
            main.main()
        setup.assert_called_once()
        login.assert_called_once()

    def test_first_start_does_not_ask_for_another_login(self):
        self.inputs.return_value = "8"
        with patch("main.create_tables"), patch("main.setup_master_password", return_value=generate_key()) as setup, patch("main.login") as login:
            main.main()
        setup.assert_called_once()
        login.assert_not_called()

    def test_session_rolls_back_and_closes_after_error(self):
        with self.assertRaises(RuntimeError):
            with database.database_session():
                raise RuntimeError("query failed")
        self.connection.rollback.assert_called_once()
        self.cursor.close.assert_called_once()
        self.connection.close.assert_called_once()

    def test_cursor_creation_failure_closes_connection(self):
        self.connection.cursor.side_effect = RuntimeError("cursor failed")
        with self.assertRaises(RuntimeError):
            with database.database_session():
                self.fail("must not yield")
        self.connection.close.assert_called_once()

    def test_table_creation_failure_releases_resources(self):
        self.cursor.execute.side_effect = RuntimeError("SQL failure")
        with self.assertRaises(RuntimeError):
            database.create_tables()
        self.connection.rollback.assert_called_once()
        self.connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
