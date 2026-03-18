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
            CREATE TABLE IF NOT EXISTS "User"(
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                tag_id TEXT
            )
        """)  

    def create_accesslog_table(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS "AccessLog" (
                log_id TEXT PRIMARY KEY,
                user_id TEXT,
                file_id TEXT,
                access_attempts INTEGER,
                timestamps TIMESTAMP,
                ip_address TEXT,
                access_status TEXT,
                FOREIGN KEY (user_id) REFERENCES "User"(user_id)
            )
        """)

    def create_file_table(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS "File" (
                file_id TEXT PRIMARY KEY,
                log_id TEXT,
                owner_id TEXT,
                file_type TEXT,
                upload_timestamp TIMESTAMP,
                file_size TEXT,
                file_name TEXT,
                FOREIGN KEY (log_id) REFERENCES AccessLog(log_id),
                FOREIGN KEY (owner_id) REFERENCES "User"(user_id)
            )
        """)

    def run(self):
        self.create_user_table()
        self.create_accesslog_table()
        self.create_file_table()
        self.con.commit()
        self.con.close()

if __name__ == "__main__":
    storage = Database()
    storage.run()
