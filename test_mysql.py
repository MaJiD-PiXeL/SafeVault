"""Opt-in MySQL connectivity test; importing this module never opens a connection."""
import os
import unittest

from database import connect_db


@unittest.skipUnless(os.getenv("SAFEVAULT_TEST_MYSQL") == "1", "MySQL integration is opt-in")
class MySQLConnectionTests(unittest.TestCase):
    def test_connection(self):
        connection = connect_db()
        try:
            self.assertTrue(connection.is_connected())
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
