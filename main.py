from database import create_tables, connect_db
from security import( hash_password,
    verify_password,
    generate_salt,
    generate_key_from_password,
    encrypt_password,
    decrypt_password,
    
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
    """اضافه کردن یک Password جدید"""

    print("\n➕ افزودن Password جدید")
    print("------------------------")

    # عنوان سرویس - اجباری
    title = input("Title: ").strip()

    if not title:
        print("❌ عنوان نمی‌تواند خالی باشد.")
        return

    # Username - اختیاری
    username = input("Username / Email (اختیاری): ").strip()

    # Password - اجباری
    password = input("Password: ").strip()

    if not password:
        print("❌ Password نمی‌تواند خالی باشد.")
        return

    # Website - اختیاری
    website = input("Website (اختیاری): ").strip()

    # Notes - اختیاری
    notes = input("Notes (اختیاری): ").strip()

    # اگر کاربر چیزی وارد نکرده، NULL ذخیره می‌کنیم
    username = username if username else None
    website = website if website else None
    notes = notes if notes else None

    # رمزنگاری Password
    encrypted_password = encrypt_password(
        password,
        encryption_key
    )

    try:

        connection = connect_db()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO passwords
            (
                title,
                username,
                encrypted_password,
                website,
                notes
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                title,
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

    except Exception as error:

        print("\n❌ خطا در ذخیره Password:")
        print(error)


def view_passwords():
    # نمایش حساب های ذخیره شده 


    print("\n📋 حساب های ذخیره شده")
    print("=" * 40)


    connection = None
    cursor = None



    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)



        cursor.execute("""
            SELECT id, title,username, website, notes
            FROM passwords
            ORDER BY id DESC

        """)
        accounts = cursor.fetchall()

        if not accounts:
            print("هنوز هیچ حسابی دخیره نشده است.")
            return



        for account in accounts:
            print("-" * 40)
            print(f"ID: {account['id']}")                       
            print(f"Service: {account['title']}")
            print(f"Username: {account['username'] or 'ثبت نشده'}")
            print(f"Website: {account['website'] or 'ثبت نشده'}")
            print(f"Notes: {account['notes'] or 'ثبت نشده'}")

        print("-" * 40)





    except Exception as error:
        print(f"❌خطا در دیافت حساب ها: {error}")

    finally:
        if cursor is not None:
            cursor.close()



        if connection is not None and connection.is_connected():
            connection.close()





def reveal_password(encryption_key):
    # رمز گشایی و نمایش رمز یک حساب


    account_id = input(
        "\nشناسه حساب مورد نظر را وارد کن"
    ).strip()


    if not account_id.isdigit():
        print("❌شناسه باید عدد باشد ")
        return



    connection = None
    cursor = None


    try:
        connection = connect_db()
        cursor = connection.cursor()


        cursor.execute(
            """
            SELECT titel, encrpted_password
            FROM passwords
            WHERE id = %s
            """,
            (int(account_id),)

        )

        account = cursor.fetchone()

        if  account is None:
            print("❌ حساب موردنظر پیدا نشد. ")


            titel, encrypt_password = account

            # رمز گشایی فقط برای حساب انتخاب شده 

            password = decrypt_password(
                encrypt_password,
                encryption_key
            )

            print("\n🔓 رمز حساب ")            
            print("=" * 35)
            print(f"Service: {titel}")
            print(f"Password: {password}")            
            print("=" * 35)

    except Exception as error:
        print(f"❌ خطا  در بازیابی رمز: {error}")    


    finally:
        if cursor is not None:
            cursor.close()



        if connection is not None and connection.is_connected():
            connection.close()










def main():
    print("=" * 40 )    
    print("         ======= 🔐Safe Vault ======= "       )
    print("=" * 40 )


    # ساخت دیتابیس و جدول ها 

    create_tables()



    # با ورود Master Password 

    encryption_key = setup_master_password()

    if not encryption_key:
        encryption_key = login()


    if not encryption_key:
        print("❌ ورود ناموفق بود ")
        return



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
            print("❌ ورود ناموفق بود.")
            return







    # menu


    while True:
        print("\n" + "=" * 40)
        print("          🔐SafeVault Menu ")
        print("=" * 40)

        print("1. ➕ Add Password")
        print("2. 📋 view Passwords")
        print("3. 🔓 Reveal Password")
        print("4. 🚪 Exit")


        choice = input("\nانتخاب شما: ").strip()

        if choice == "1":

            add_password(encryption_key)

        elif choice == "2":
            view_passwords()



        elif choice == "3":
            reveal_password(encryption_key)

        

        elif choice == "4":
            print("\n👋 SafeVault بسته شد.")
            break
            


        else:
            print("\n❌ انتخاب نامعتبر است.")


if __name__ == "__main__":
    main()
