import sqlite3
from pathlib import Path



DATA_DIR = Path("data")

DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "vault.db"



# اتصال به دیتابیس
def connect_db():
    return sqlite3.connect(DB_PATH)

# ساخت جدول هایی مورد نیاز 
def create_tables():
    connection = connect_db()
    cursor = connection.cursor()

    # vault جدول تنظیمات و اطلاعات اصلی 
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFULT CURRENT_TIMESTAMP
    )

""")


    # جدول حساب های کاربر 
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            username TEXT,
            encrypted_password TEXT NOT NULL,
            website TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

    connection.commit()
    connection.close()
    