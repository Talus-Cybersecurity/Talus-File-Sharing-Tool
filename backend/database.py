from .schema import Schema

# Handles SQL logic
class Database:
    def __init__(self): 
        self.schema = Schema()
        # new_registration = ""
    
    # When a user tries to log in, retrieve their account information from the database to 
    # verify their credentials
    
    def get_username(self, username: str):
        self.schema.cur.execute("""
            SELECT username FROM public."User" 
            WHERE username = %s """, (username, ))
        return self.schema.cur.fetchone()
        
    def get_password(self, username: str):
        self.schema.cur.execute("""
            SELECT password FROM public."User" 
            WHERE username = %s""", (username, ))
        
        row = self.schema.cur.fetchone()   
        return row[0] if row else None # returns user's password
    

    def get_user_id(self, username: str):
        self.schema.cur.execute("""
            SELECT user_id FROM public."User"
            WHERE username = %s""", (username,))
        row = self.schema.cur.fetchone()
        return row[0] if row else None # returns user's user_id

    def get_file_policy(self, file_id: str): # return FilePolicy row given the file_id
        self.schema.cur.execute("""
            SELECT ip_address, access_count, hour_range,
                device_verification, location, watermark, biometrics
            FROM "FilePolicy"
            WHERE file_id = %s
        """, (file_id,))
        return self.schema.cur.fetchone(()

    # Return how many times file has been accessed
    def get_access_count(self, file_id: str) -> int:
        self.schema.cur.execute("""
            SELECT COUNT(*) FROM "AccessLog"
            WHERE file_id = %s
            AND access_status = 'granted'
        """, (file_id,))
        row = self.schema.cur.fetchone()
        return row[0] if row else 0

    def check_if_user_exists(self, username):
        self.schema.cur.execute("""
            SELECT username FROM "User"
            WHERE username = %s""", (username, ))
        return self.schema.cur.fetchone() is not None
        
    # Insert user account information into the database when a new user registers
    def insert_user(self, user_id, username, email, password, tag_id):
        try:
            self.schema.cur.execute("""
                INSERT INTO "User" (user_id, username, email, password, tag_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, username, email, password, tag_id))
            self.schema.con.commit()
        except Exception:
            self.schema.con.rollback()
            raise
    
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
