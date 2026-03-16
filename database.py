import psycopg2
from Cryptography import hash_password

class Database:
    def __init__(self): 
        self.con = psycopg2.connect(
            host="localhost",
            database="talus_db",
            user="michelle",
            password="1234"
        )
        self.cur = self.con.cursor()

    def create_user_table(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS users(
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                tag_id TEXT
            )
        """)  

    def create_accesslog_table(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS accesslog (
                log_id TEXT PRIMARY KEY,
                user_id TEXT,
                file_id TEXT,
                access_attempts INTEGER,
                timestamps TIMESTAMP,
                ip_address TEXT,
                access_status TEXT
            )
        """)

    def run(self):
        self.create_user_table()
        self.create_accesslog_table()
        self.con.commit()
        self.con.close()

if __name__ == "__main__":
    storage = Database()
    storage.run()
