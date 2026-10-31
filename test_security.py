import hashlib
import unittest

from cryptography.fernet import InvalidToken

from security import (
    decrypt_password, encrypt_password, generate_key,
    generate_key_from_password, generate_salt, hash_password, verify_password,
)


class SecurityTests(unittest.TestCase):
    def test_encryption_preserves_unicode_and_whitespace(self):
        key = generate_key()
        password = "  رمز عبور 🔐  "
        token = encrypt_password(password, key)
        self.assertNotIn(password, token)
        self.assertEqual(decrypt_password(token, key), password)

    def test_wrong_key_and_modified_ciphertext_are_rejected(self):
        key = generate_key()
        token = encrypt_password("secret", key)
        with self.assertRaises(InvalidToken):
            decrypt_password(token, generate_key())
        with self.assertRaises(InvalidToken):
            decrypt_password(token[:-5] + "AAAAA", key)

    def test_salts_are_random_and_have_expected_length(self):
        first, second = generate_salt(), generate_salt()
        self.assertEqual(len(first), 16)
        self.assertNotEqual(first, second)

    def test_key_derivation_is_stable_and_salt_specific(self):
        salt = generate_salt()
        key = generate_key_from_password("master", salt)
        self.assertEqual(key, generate_key_from_password("master", salt))
        self.assertNotEqual(key, generate_key_from_password("master", generate_salt()))

    def test_salted_hash_authentication(self):
        salt = generate_salt()
        stored = hash_password("master", salt)
        self.assertEqual(len(stored), 64)
        self.assertTrue(verify_password("master", stored, salt))
        self.assertFalse(verify_password("wrong", stored, salt))
        self.assertFalse(verify_password("master", stored, generate_salt()))

    def test_verifier_does_not_reveal_encryption_key(self):
        import base64
        salt = generate_salt()
        verifier = bytes.fromhex(hash_password("master", salt))
        key = base64.urlsafe_b64decode(generate_key_from_password("master", salt))
        self.assertNotEqual(verifier, key)

    def test_legacy_hashes_still_authenticate(self):
        stored = hashlib.sha256(b"legacy").hexdigest()
        self.assertTrue(verify_password("legacy", stored, generate_salt()))
        self.assertFalse(verify_password("wrong", stored, generate_salt()))


if __name__ == "__main__":
    unittest.main()
