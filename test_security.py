from security import generate_key, encrypt_password, decrypt_password


# ساخت کلید
key = generate_key()

print("🔑 Key:")
print(key.decode())


# رمز اصلی
password = "MySecret123"


# رمزنگاری
encrypted = encrypt_password(password, key)

print("\n🔐 Encrypted:")
print(encrypted)


# رمزگشایی
decrypted = decrypt_password(encrypted, key)

print("\n🔓 Decrypted:")
print(decrypted)