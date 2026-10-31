import mysql.connector
import os
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


def connect_db():
    """اتصال به MySQL"""

    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        port=int(os.getenv("MYSQL_PORT", "3306")),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "safevault"),
        charset="utf8mb4",
        connection_timeout=10,
    )


@contextmanager
def database_session(dictionary=False):
    """Always release the cursor and connection, including on SQL errors."""
    connection = connect_db()
    try:
        cursor = connection.cursor(dictionary=dictionary)
        try:
            yield connection, cursor
        except BaseException:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()


def create_tables():
    """ساخت جدول‌های SafeVault"""

    with database_session() as (connection, cursor):
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
