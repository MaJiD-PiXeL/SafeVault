from database import create_tables, connect_db, database_session
from getpass import getpass
from cryptography.fernet import InvalidToken
from security import( hash_password,
    verify_password,
    generate_salt,
    generate_key_from_password,
    encrypt_password,
    decrypt_password,
    
)
                     

def setup_master_password():
    """Create the first master password and return its encryption key."""
    with database_session() as (connection, cursor):
        cursor.execute("SELECT password_hash FROM vault LIMIT 1")
        if cursor.fetchone():
            return None

        print("\n🔐 ساخت Master Password")
        password = getpass("Master Password: ")
        confirm_password = getpass("تکرار Master Password: ")
        if not password:
            print("❌ رمز عبور نمی‌تواند خالی باشد.")
            return None
        if password != confirm_password:
            print("❌ رمزها یکسان نیستند.")
            return None

        salt = generate_salt()
        cursor.execute(
            "INSERT INTO vault (password_hash, salt) VALUES (%s, %s)",
            (hash_password(password, salt), salt.hex()),
        )
        connection.commit()

    print("\n✅ Master Password با موفقیت ساخته شد!")
    return generate_key_from_password(password, salt)


def login():
    """Authenticate existing vaults and upgrade legacy password hashes."""
    with database_session() as (connection, cursor):
        cursor.execute("SELECT id, password_hash, salt FROM vault ORDER BY id LIMIT 1")
        result = cursor.fetchone()
        if not result:
            print("❌ Master Password هنوز ساخته نشده.")
            return None

        vault_id, stored_hash, salt_hex = result
        salt = bytes.fromhex(salt_hex)
        password = getpass("Master Password: ")
        if not verify_password(password, stored_hash, salt):
            print("\n❌ Master Password اشتباه است.")
            return None

        upgraded_hash = hash_password(password, salt)
        if stored_hash != upgraded_hash:
            cursor.execute(
                "UPDATE vault SET password_hash = %s WHERE id = %s AND password_hash = %s",
                (upgraded_hash, vault_id, stored_hash),
            )
            connection.commit()

    print("\n✅ ورود موفق بود!")
    return generate_key_from_password(password, salt)


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
    password = getpass("Password: ")

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
        with database_session() as (connection, cursor):
            cursor.execute(
                """INSERT INTO passwords
                (title, username, encrypted_password, website, notes)
                VALUES (%s, %s, %s, %s, %s)""",
                (title, username, encrypted_password, website, notes),
            )
            connection.commit()
        print("\n✅ Password با موفقیت ذخیره شد!")
    except Exception as error:
        print(f"\n❌ خطا در ذخیره Password: {error}")


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




def search_password():
    # جستجوی حساب ها بر  اساس عنوان نام کاربری یا وب سایت 
    print("\n🔎 جستجوی حساب ها ")
    print("=" * 40)



    search_query = input(
        "نام سرویس نام کاربری یا وب سایت را وارد کنید: "
    ).strip()


    if not search_query:
        print("❌ عبارت جستجو نمی‌تواند خالی باشد. ")
        return



    connection = None

    cursor = None



    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)


        query = """
            SELECT id,title, username, website, notes
            FROM passwords
            WHERE title LIKE %s
                OR username LIKE %s
                OR website LIKE %s
            ORDER BY id DESC
        """

        search_pattern = f"%{search_query}%"


        cursor.execute(
            query,
            (search_pattern, search_pattern, search_pattern)
        )

        accounts = cursor.fetchall()

        if not accounts:
            print("\n❌ هیچ حسابی پیدا نشد.")
            return


        print(f"\n✅ تعداد نتایج: {len(accounts)}")


        for account in accounts:
            print("\n" + "-" * 40)            
            print(f"ID: {account['id']}")
            print(f"Service: {account['title']}")
            print(
                f"Username: "
                f"{account['username'] or 'ثبت نشده'}"
            )
            print(
                f"Website: "
                f"{account['website'] or 'ثبت نشده'}"
            )
            print(
                f"Notes: "
                f"{account['notes'] or 'ثبت نشده'}"
            )

        print("-" * 40)


    except  Exception  as error:
        print(f"\n❌ خطا در جستجوی حساب‌ها: {error}")


    finally:
        if cursor is not None:
            cursor.close()


        if connection is not None and connection.is_connected():
            connection.close()



def edit_password(encryption_key):

    connection = None
    cursor = None



    try:
        connection = connect_db()
        cursor = connection.cursor(dictionary=True)



        account_id = input("Enter the account ID you want to edit: ").strip()

        if not account_id.isdecimal():
            print("Invalid ID. Please enter a valid numeric ID.")
            return


        account_id = int(account_id)


        cursor.execute(
            """
            SELECT id, title, username, encrypted_password, website, notes
            FROM passwords
            WHERE id = %s
            """,
            (account_id,)
        )

        account = cursor.fetchone()

        if not account:
            print("No account found with this ID.")
            return


        while True:
            print("\n========== Edit Password ==========")
            print(f"Account: {account['title']}")
            print("1. Edit Title")
            print("2. Edit Username / Email")            
            print("3. Edit Password")
            print("4. Edit Website")
            print("5. Edit Notes")
            print("6. Finish Editing")
            print("=" * 25)



            choice = input("Enter your choice: ").strip()



            fields = {
                "1": ("title", "Title"),
                "2": ("username", "Username / Email"),
                "3": ("encrypted_password", "Password"),
                "4": ("website", "Website"),
                "5":("notes", "Notes"),

            }

            if choice == "6":
                print("Editing finished.")
                break

            if choice not in fields:
                print("Invalid choice. Please try again.")
                continue

            field,field_name = fields[choice]


            if field == "encrypted_password":
                new_value = getpass("Enter the new Password: ")
            else:
                new_value = input(f"Enter the new {field_name}: ").strip()


            if field in ("title","encrypted_password") and not new_value:
                print(f"{field_name} cannot be empty.")
                continue

            if field in ("username", "website", "notes"):
                new_value = new_value if new_value else None


            if field == "encrypted_password":
                new_value = encrypt_password(new_value, encryption_key)

            cursor.execute(
                f"UPDATE passwords SET {field} = %s WHERE id = %s ",
                (new_value, account_id)
            )

            connection.commit()


            account[field] = new_value

            print(f"{field_name} updated successfully!")
    except Exception as error:
        if connection:
            connection.rollback()

        print(f"An error occurred while editing the account: {error}")



    finally:
        if cursor:
            cursor.close()


        if connection:
            connection.close()


def delete_password():
    connection = None
    cursor = None


    try:
        connection = connect_db()

        cursor = connection.cursor(dictionary=True)


        cursor.execute(
            """
            SELECT id, title, username, website, notes
            FROM passwords
            ORDER BY id DESC
            """
        )

        accounts = cursor.fetchall()

        if not accounts:
            print("No saved accounts found.")
            return

        print("\n========== Saved Accounts ==========")

        for account in accounts:
            print(f"ID: {account['id']}")            
            print(f"Title: {account['title']}")            
            print(f"Username: {account['username'] or 'Not set'}")
            print(f"Website: {account['website'] or 'Not set'}")
            print(f"Notes: {account['notes'] or 'Not set'}")
            print("------------------------------------")



        account_id = input(
            "Enter the ID of the account to delete: "
        ).strip()



        if not account_id.isdecimal():
            print("Invalid ID. Please enter a numeric ID.")
            return

        account_id = int(account_id)



        cursor.execute(
            "SELECT id, title FROM passwords WHERE id = %s",
            (account_id,)
        )



        account = cursor.fetchone()




        if not account:
            print("No account found with this ID.")
            return


        print(f"\nselected account: {account['title']}")


        confirmation = input(
            "Type DELETE to confirm deletion: "
        ).strip()


        if confirmation != "DELETE":
            print("Deletion cancelled")
            return


        cursor.execute(
            "DELETE FROM passwords WHERE id = %s",
            (account_id,)
        )



        connection.commit()



        print("Account deleted successfully!")


    except Exception as error:
        if connection:
            connection.rollback()



        print(f"An error occurred while deleting the account: {error}")



    finally:
        if cursor:
            cursor.close()


        if connection:
            connection.close()



def reveal_password(encryption_key):
    # رمز گشایی و نمایش رمز یک حساب


    account_id = input(
        "\nشناسه حساب مورد نظر را وارد کن"
    ).strip()


    if not account_id.isdecimal():
        print("❌شناسه باید عدد باشد ")
        return



    connection = None
    cursor = None


    try:
        connection = connect_db()
        cursor = connection.cursor()


        cursor.execute(
            """
            SELECT title, encrypted_password
            FROM passwords
            WHERE id = %s
            """,
            (int(account_id),)

        )

        account = cursor.fetchone()

        if account is None:
            print("❌ حساب موردنظر پیدا نشد.")
            return

        title, encrypted_password = account
        password = decrypt_password(encrypted_password, encryption_key)
        print("\n🔓 رمز حساب")
        print("=" * 35)
        print(f"Service: {title}")
        print(f"Password: {password}")
        print("=" * 35)

    except InvalidToken:
        print("❌ رمز ذخیره‌شده معتبر نیست یا کلید آن متفاوت است؛ رمز حساب را دوباره ویرایش و ذخیره کنید.")
    except Exception as error:
        print(f"❌ خطا در بازیابی رمز: {error}")


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



    # menu


    while True:
        print("\n" + "=" * 40)
        print("          🔐SafeVault Menu ")
        print("=" * 40)

        print("1. ➕ Add Password")
        print("2. 📋 view Passwords")
        print("3. 🔓 Reveal Password")
        print("4. 🔎 Search Password")
        print("5. ✏️  Edit Password")
        print("6. 🗑️  Delete Password")
        print("8. 🚪 Exit")


        choice = input("Enter your choice: ").strip()

        if choice == "1":

            add_password(encryption_key)

        elif choice == "2":
            view_passwords()



        elif choice == "3":
            reveal_password(encryption_key)



        elif choice == "4":
            search_password()



        elif choice == "5":
            edit_password(encryption_key)



        elif choice == "6":
            delete_password()

        

        elif choice == "8":
            print("SafeVault closed. Goodbye!")
            break
            


        else:
            print("\n❌ انتخاب نامعتبر است.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nSafeVault closed.")
    except Exception as error:
        raise SystemExit(f"SafeVault could not continue: {error}")

