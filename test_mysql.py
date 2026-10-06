from database import connect_db


try:

    connection = connect_db()

    print("✅ اتصال به MySQL موفق بود!")

    connection.close()

except Exception as error:

    print("❌ خطا در اتصال به MySQL:")
    print(error)