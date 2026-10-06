from security import (
    generate_salt,
    generate_key_from_password,
    encrypt_password,
    decrypt_password
)


# Master Password
master_password = "MyMasterPassword123"


# ساخت Salt
salt = generate_salt()

print("Salt:")
print(salt)


# ساخت Encryption Key
key = generate_key_from_password(
    master_password,
    salt
)

print("\nEncryption Key:")
print(key)


# Password واقعی
password = "GmailPassword123"


# رمزنگاری
encrypted = encrypt_password(
    password,
    key
)

print("\nEncrypted Password:")
print(encrypted)


# رمزگشایی
decrypted = decrypt_password(
    encrypted,
    key
)

print("\nDecrypted Password:")
print(decrypted)