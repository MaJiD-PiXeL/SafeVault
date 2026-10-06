import hashlib

from cryptography.fernet import Fernet




# بخش Master Password 


def hash_password(password):
    # تبدیل Master Password به Hash
    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()






def verify_password(password, stored_hash):

    # برسی درست بودن Master Password

    return hash_password(password) == stored_hash





# بخش encryption


def generate_key():
    # ساخت یک  کلید رمز نگاری جدید 
    return Fernet.generate_key()


def encrypt_password(password, key):

    # رمزنگاری password
    
    cipher = Fernet(key)

    encrypted = cipher.encrypt(
        password.encode("utf-8")
    )
    return encrypted.decode("utf-8")


def decrypt_password(encrypt_password, key):

    cipher = Fernet(key)


    decrypted = cipher.decrypt(
        encrypt_password.encode("utf-8")
    )

    return decrypted.decode("utf-8")





