import hashlib



def hash_password(password):
    # تبدیل رمز عبور به هش 

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()



def verify_password(password, stored_hash):
    # بررسی درست بودن رمز 


    return hash_password(password) == stored_hash