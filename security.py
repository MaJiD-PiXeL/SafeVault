import hashlib
import base64
import os


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




# ساخت Encryption Key


def generate_key_from_password(password, salt):

    # ساخت کلید رمزنگاری از Master Password

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000,
        dklen=32
    )

    return base64.urlsafe_b64encode(key)










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




# Decryption


def decrypt_password(encrypt_password, key):
    # رمزگشایی password

    cipher = Fernet(key)


    decrypted = cipher.decrypt(
        encrypt_password.encode("utf-8")
    )

    return decrypted.decode("utf-8")




# ساخت salt

def generate_salt():

    # ساخت salt تصادفی 

    return os.urandom(16)




