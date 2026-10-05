from database import create_tables, connect_db
from security import hash_password, verify_password

def setup_master_password():
    # در اولین اجرای برنامه master password ساخت 


    connection = connect_db()
    cursor = connection.cursor()


    # برسی میکنیم قبلا Master password ساخته شده یا نه 
    cursor.execute("SELECT password_hash FROM vault LIMIT 1 ")
    result = cursor.fetchone()

    # اگر قبلا ساخته شده باشه 
    if result:
        connection.close()
        return False

    print("\n🔐ساخت Master password")
    print("------------------------")



    password = input("Master Password: ")
    confirm_password = input("تکرار Master Password : ")



    # برسی خالی نبودن رمز 
    if not password:
        print("❌ رمز عبور نمیتواند خالی باشد ")
        connection.close()
        return False



    # برسی یکسان بودن رمز ها 
    if password != confirm_password:
        print("❌ رمز ها یکسان نیستند ")
        connection.close()
        return False



    # تبدیل رمز به Hash
    hashed_password = hash_password(password)


    # ذخیره Hash در دیتابیس 
    cursor.execute(
        "INSERT INTO vault (password_hash) VALUES (?)",
        (hashed_password,)
    )

    connection.commit()
    connection.close()

    print("\n✅ Master Password با موفقیت ساخته شد ")

    return True



def login():
    # ورود به safevault

    connection = connect_db()
    cursor = connection.cursor()
    
    
    cursor.execute("SELECT password_hash FROM vault LIMIT 1 ")


    result = cursor.fetchone()


    connection.close()

    if not result:
        return False


    stored_hash = result[0]

    print("\n🔐 ورود به SafeVault")
    print("----------------------")



    password = input("Master Password: ")

    if verify_password(password,stored_hash):
        print("\n✅ ورود موفق بود! ")
        return True


    print("\n❌ Master Password اشتباه است.")
    return False

def main():
    print("=============================================" )    
    print("         ======= 🔐Safe Vault ======= "       )
    print("=============================================" )


    # ساخت دیتابیس و جدول ها 

    create_tables()


    # اگر Master Password وجود ندارد 
    if setup_master_password():
        print("\n🚀وارد Vault شدید!")
        return


    # اگر وجود دارد ورود انجام شود 
    login()

if __name__ == "__main__":
    main()