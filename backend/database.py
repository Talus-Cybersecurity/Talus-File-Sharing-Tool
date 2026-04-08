from backend.schema import Schema

# Handles SQL logic
class Database:
    def __init__(self): 
        self.schema = Schema()
        # new_registration = ""
    
    # When a user tries to log in, retrieve their account information from the database to 
    # verify their credentials
    """
    In server.py
    if user tries to log in, then 
    username.var = username
    self.database.get_user(self, username.var)

    """
    # def check_username(self, username):
    #     self.schema.cur.execute("""
    #         SELECT username

    #     """)
    # def get_password(self, username):
    #     self.schema.cur.execute("""
    #         SELECT password 
    #         FROM "User" 
    #         WHERE username = %s
    #      """, (username, ))
    #     return self.schema.cur.fetchone()   # returns password


    def check_if_user_exists(self, username):
        self.schema.cur.execute("""
            SELECT username FROM "User"
            WHERE username = %s""", (username, ))
        return self.schema.cur.fetchone() is not None
        
    
    # Insert user account information into the database when a new user registers
    def insert_user(self, user_id, username, password, tag_id):
        self.schema.cur.execute("""
            INSERT INTO "User" (user_id, username, password, tag_id) 
            VALUES (%s, %s, %s, %s)
        """, (user_id, username, password, tag_id))
        self.schema.con.commit()
    
    # Insert file information into the database when a user uploads a file
    def insert_file(self, file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path):
        self.schema.cur.execute("""
            INSERT INTO "File" (file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path))
        self.schema.con.commit()

    # Insert access log information into the database when a user attempts to access a file
    def insert_access_log(self, log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status):
        self.schema.cur.execute("""
            INSERT INTO "AccessLog" (log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status))
        self.schema.con.commit()

    # Insert file policy information into the database when a user shares a file with another user
        def insert_file_policy(self, policy_id, receiver_id, file_id,
            ip_address, access_count, active_permissions,
            device_verification, location, account_info,
            watermark, data_range, time, biometrics):
        self.schema.cur.execute("""
            INSERT INTO "FilePolicy" (policy_id, receiver_id, file_id, ip_address, access_count, active_permissions,
                device_verification, location, account_info, watermark, data_range, time, biometrics)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            policy_id, receiver_id, file_id,
            ip_address, access_count, active_permissions,
            device_verification, location, account_info,
            watermark, data_range, time, biometrics
        ))
        self.schema.con.commit()

# SECTION TO TEST DATABASE INSERTIONS
    # def run_tests(self):
    #     self.insert_user("user1", "alice", "hashed_password1", "tag1")
    #     self.insert_file("file1", "log1", "user1", "pdf", "2024-06-01T12:00:00Z", "2MB", "report.pdf")
    #     self.insert_file_policy("policy1", "file1", "read-only", "2024-12-31T23:59:59Z")
    #     self.insert_access_log("log1", "user1", "file1", 1, "2024-06-01T12:05:00Z")

# if __name__ == "__main__":
#     db = Database()
