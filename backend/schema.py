import psycopg2
import os
from dotenv import load_dotenv
load_dotenv()

# Manages connection and table creation
class Schema:
    def __init__(self): 
        self.con = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            port=os.getenv("DB_PORT", "5432")
        )
        self.cur = self.con.cursor()

    def create_user_table(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS "User"(
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
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
                file_path TEXT,
                FOREIGN KEY (log_id) REFERENCES "AccessLog"(log_id),
                FOREIGN KEY (owner_id) REFERENCES "User"(user_id)
            )
        """)

    def create_filepolicy_table(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS "FilePolicy" (
                policy_id TEXT PRIMARY KEY,
                receiver_id TEXT,
                file_id TEXT,
                ip_address TEXT,
                access_count INTEGER,
                active_permissions BOOLEAN,
                device_verification BOOLEAN,
                location TEXT,
                account_info TEXT,  
                watermark TEXT,
                data_range TEXT,
                time TIMESTAMP,
                biometrics TEXT,       
                FOREIGN KEY (receiver_id) REFERENCES "User"(user_id),
                FOREIGN KEY (file_id) REFERENCES "File"(file_id)
            )
        """)

    def delete_all_tables(self):
        self.cur.execute("""DROP TABLE IF EXISTS "FilePolicy" CASCADE;""")
        self.cur.execute("""DROP TABLE IF EXISTS "File" CASCADE;""")
        self.cur.execute("""DROP TABLE IF EXISTS "AccessLog" CASCADE;""")
        self.cur.execute("""DROP TABLE IF EXISTS "User" CASCADE;""")
        self.con.commit()

    def run(self):
        self.create_user_table()
        self.create_accesslog_table()
        self.create_file_table()
        self.create_filepolicy_table()
        # self.delete_all_tables()
        self.con.commit()
        self.con.close()

if __name__ == "__main__":
    storage = Schema()
    storage.run()