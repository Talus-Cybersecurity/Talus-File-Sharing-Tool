from schema import Schema

# Handles SQL logic
class Database:
    def __init__(self): 
        self.schema = Schema()
    
    def insert_user(self, user_id, username, password, tag_id):
        self.schema.cur.execute("""
            INSERT INTO "User" (user_id, username, password, tag_id) 
            VALUES (%s, %s, %s, %s)
        """, (user_id, username, password, tag_id))
        self.schema.con.commit()
    
    def insert_file(self, file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path):
        self.schema.cur.execute("""
            INSERT INTO "File" (file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path))
        self.schema.con.commit()

    def insert_access_log(self, log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status):
        self.schema.cur.execute("""
            INSERT INTO "AccessLog" (log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status))
        self.schema.con.commit()

    def insert_file_policy(self, policy_id, file_id, access_level, expiration_date):
        self.schema.cur.execute("""
            INSERT INTO "FilePolicy" (policy_id, file_id, access_level, expiration_date)
            VALUES (%s, %s, %s, %s)
        """, (policy_id, file_id, access_level, expiration_date))
        self.schema.con.commit()

# SECTION TO TEST DATABASE INSERTIONS
    # def run_tests(self):
    #     self.insert_user("user1", "alice", "hashed_password1", "tag1")
    #     self.insert_file("file1", "log1", "user1", "pdf", "2024-06-01T12:00:00Z", "2MB", "report.pdf")
    #     self.insert_file_policy("policy1", "file1", "read-only", "2024-12-31T23:59:59Z")
    #     self.insert_access_log("log1", "user1", "file1", 1, "2024-06-01T12:05:00Z")

# if __name__ == "__main__":
#     db = Database()