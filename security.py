"""Password verification and encryption for the local vault."""
import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet


PBKDF2_ITERATIONS = 600_000


def hash_password(password, salt):
    """Store a salted verifier distinct from the vault's encryption key."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), b"safevault:verify:" + salt,
        PBKDF2_ITERATIONS, dklen=32,
    ).hex()


def verify_password(password, stored_hash, salt):
    if hmac.compare_digest(hash_password(password, salt), stored_hash):
        return True
    # Read compatibility only. Login replaces legacy SHA-256 verifiers.
    legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_hash, stored_hash)


def generate_key_from_password(password, salt):
    # Preserve this derivation so existing vaults remain readable.
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt,
        PBKDF2_ITERATIONS, dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def generate_key():
    return Fernet.generate_key()


def encrypt_password(password, key):
    return Fernet(key).encrypt(password.encode("utf-8")).decode("utf-8")


def decrypt_password(encrypted_password, key):
    return Fernet(key).decrypt(encrypted_password.encode("utf-8")).decode("utf-8")


def generate_salt():
    return os.urandom(16)
