from database import create_tables, connect_db
from security import( hash_password,
    verify_password,
    generate_salt,
    generate_key_from_password,
    encrypt_password
)
                     

def setup_master_password():
    """ساخت Master Password در اولین اجرای برنامه"""

    connection = connect_db()
    cursor = connection.cursor()

    # بررسی می‌کنیم قبلاً Master Password ساخته شده یا نه
    cursor.execute(
        "SELECT password_hash FROM vault LIMIT 1"
    )

    result = cursor.fetchone()

    # اگر قبلاً ساخته شده باشد
    if result:
        cursor.close()
        connection.close()
        return False

    print("\n🔐 ساخت Master Password")
    print("------------------------")

    password = input("Master Password: ")
    confirm_password = input("تکرار Master Password: ")

    # بررسی خالی نبودن رمز
    if not password:
        print("❌ رمز عبور نمی‌تواند خالی باشد.")

        cursor.close()
        connection.close()

        return False

    # بررسی یکسان بودن رمزها
    if password != confirm_password:
        print("❌ رمزها یکسان نیستند.")

        cursor.close()
        connection.close()

        return False

    # تبدیل Master Password به Hash
    hashed_password = hash_password(password)


    # ساخت salt تصادفی 
    salt = generate_salt()

    # تبدیل salt به متن برای mysql

    salt_hex = salt.hex()



    # دخیره در mysql

    cursor.execute(
        """
        INSERT INTO vault
        (password_hash, salt)
        VALUES (%s, %s)
        """,
        (hashed_password, salt_hex)
    )

    connection.commit()

    cursor.close()
    connection.close()

    print("\n✅ Master Password با موفقیت ساخته شد!")

    encryption_key = generate_key_from_password(
        password,
        salt

    )
    return encryption_key


def login():
    """ورود به SafeVault"""

    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT password_hash, salt
        FROM vault
        LIMIT 1
        """
    )

    result = cursor.fetchone()

    cursor.close()
    connection.close()

    # اگر Master Password وجود نداشت
    if not result:

        print("❌ Master Password هنوز ساخته نشده.")

        return None

    # Hash و Salt را از دیتابیس می‌گیریم
    stored_hash = result[0]
    salt_hex = result[1]

    print("\n🔐 ورود به SafeVault")
    print("--------------------")

    password = input("Master Password: ")

    # بررسی Master Password
    if not verify_password(password, stored_hash):

        print("\n❌ Master Password اشتباه است.")

        return None

    # تبدیل Salt از Hex به Bytes
    salt = bytes.fromhex(salt_hex)

    # ساخت Encryption Key
    encryption_key = generate_key_from_password(
        password,
        salt
    )

    print("\n✅ ورود موفق بود!")

    return encryption_key


def add_password(encryption_key):

    # اضافه کردن یک password جدید 




    print("\n➕ افزودن password جدید ")
    print("------------------------------")



    titel = input("Titel: ")
    username = input("Username / Email: ")
    password = input("Password: ")
    website = input("Website: ")
    notes = input("Notes: ")



    # برسی عنوان 
    if not titel:
        print("❌ Titel نمی‌تواند خالی باشد.")
        return


    # برسی رمز 
    if not password:
        print("❌ Password نمی‌تواند خالی باشد.")
        return


    # رمزنگاری password
    encrypted_password = encrypt_password(
        password,
        encryption_key
    )



    # اتصال به mysql

    connection = connect_db()
    cursor = connection.cursor()



    cursor.execute(
        """
        INSERT INTO passwords
        (
            titel,
            username,
            encrypted_password,
            website,
            notes
        )
        VALUES(%s, %s, %s, %s, %s)

        """,
        (
            titel,
            username,
            encrypted_password,
            website,
            notes
        )
    )

    connection.commit()


    cursor.close()
    connection.close()
    print("\n✅ Password با موفقیت ذخیره شد!")




def main():
    print("=============================================" )    
    print("         ======= 🔐Safe Vault ======= "       )
    print("=============================================" )


    # ساخت دیتابیس و جدول ها 

    create_tables()



    # ساخت Master Password
    if setup_master_password():

        print("\n🚀 Vault آماده استفاده است!")

        # برای اولین ورود باید کلید بسازیم 
        password = input("\nبرای ورود دوباره Master Password را وارد کن: ")

        connection = connect_db()
        cursor = connection.cursor()


        cursor.execute(
            "SELECT password_hash, salt FROM vault LIMIT 1 "
        )


        result = cursor.fetchone()

        cursor.close()
        connection.close()




        stored_hash = result[0]
        salt = bytes.fromhex(result[1])



        encryption_key = generate_key_from_password(
            password,
            salt

        )
    else:
        # ورود
        encryption_key = login()

        if not encryption_key:
            return







    # menu


    while True:
        print("\n====================================")
        print("          🔐SafeVault Menu ")
        print("\n====================================")

        print("1. ➕ Add Password")
        print("2. 🚪 Exit")


        choice = input("\nانتخاب شما: ")

        if choice == "1":

            add_password(encryption_key)

        elif choice == "2":
            break


        else:
            print("\n❌ انتخاب نامعتبر است.")
