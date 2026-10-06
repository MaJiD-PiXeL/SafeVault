import mysql.connector


def connect_db():
    """اتصال به MySQL"""

    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="M@jid1382",
        database="safevault"
    )


def create_tables():
    """ساخت جدول‌های SafeVault"""

    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INT AUTO_INCREMENT PRIMARY KEY,
            password_hash VARCHAR(64) NOT NULL,
            salt VARCHAR(32) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            username VARCHAR(255),
            encrypted_password TEXT NOT NULL,
            website VARCHAR(500),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()

    cursor.close()
    connection.close()