from .schema import Schema
import psycopg2

# Handles SQL logic
class Database:
    def __init__(self):
        self.schema = Schema()

    def _execute(self, query, params=()):
        """Execute a query, auto-recovering from aborted transactions."""
        try:
            self.schema.cur.execute(query, params)
        except psycopg2.errors.InFailedSqlTransaction:
            self.schema.con.rollback()
            self.schema.cur.execute(query, params)
        # new_registration = ""
    
    # When a user tries to log in, retrieve their account information from the database to 
    # verify their credentials
    
    def get_username(self, username: str):
        self._execute("""
            SELECT username FROM public."User" 
            WHERE username = %s """, (username, ))
        return self.schema.cur.fetchone()
        
    def get_password(self, username: str):
        self._execute("""
            SELECT password FROM public."User" 
            WHERE username = %s""", (username, ))
        
        row = self.schema.cur.fetchone()   
        return row[0] if row else None # returns user's password
    

    def get_user_id(self, username: str):
        self._execute("""
            SELECT user_id FROM public."User"
            WHERE username = %s""", (username,))
        row = self.schema.cur.fetchone()
        return row[0] if row else None # returns user's user_id

    def get_file_policy(self, file_id: str): # return FilePolicy row given the file_id
        self._execute("""
            SELECT ip_address, access_count, hour_range,
                device_verification, location, watermark, biometrics
            FROM "FilePolicy"
            WHERE file_id = %s
        """, (file_id,))
        return self.schema.cur.fetchone()

    def check_if_user_exists(self, username):
        self._execute("""
            SELECT username FROM "User"
            WHERE username = %s""", (username, ))
        return self.schema.cur.fetchone() is not None
        
    # Insert user account information into the database when a new user registers
    def get_public_key(self, username: str):
        self._execute("""
            SELECT public_key FROM public."User"
            WHERE username = %s""", (username,))
        row = self.schema.cur.fetchone()
        return row[0] if row else None

    def get_key_bundle(self, username: str):
        self._execute("""
            SELECT encrypted_private_key, pbkdf2_salt, aes_iv
            FROM public."User"
            WHERE username = %s""", (username,))
        row = self.schema.cur.fetchone()
        if not row:
            return None, None, None
        return row[0], row[1], row[2]

    def insert_user(self, user_id, username, email, password, tag_id,
                    public_key=None, encrypted_private_key=None,
                    pbkdf2_salt=None, aes_iv=None):
        try:
            self._execute("""
                INSERT INTO "User" (user_id, username, email, password, tag_id,
                                    public_key, encrypted_private_key,
                                    pbkdf2_salt, aes_iv)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, username, email, password, tag_id,
                  public_key, encrypted_private_key, pbkdf2_salt, aes_iv))
            self.schema.con.commit()
        except Exception:
            self.schema.con.rollback()
            raise
    
    def delete_file(self, file_id: str):
        try:
            self._execute("""DELETE FROM "File" WHERE file_id = %s""", (file_id,))
            self.schema.con.commit()
        except Exception:
            self.schema.con.rollback()
            raise

    def delete_file_policy(self, file_id: str):
        try:
            self._execute("""DELETE FROM "FilePolicy" WHERE file_id = %s""", (file_id,))
            self.schema.con.commit()
        except Exception:
            self.schema.con.rollback()
            raise

    # Insert file information into the database when a user uploads a file
    def insert_file(self, file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path):
        try:
            self._execute("""
                INSERT INTO "File" (file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (file_id, log_id, owner_id, file_type, upload_timestamp, file_size, file_name, file_path))
            self.schema.con.commit()
        except Exception:
            self.schema.con.rollback()
            raise

    # Insert access log information into the database when a user attempts to access a file
    def insert_access_log(self, log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status):
        try:
            self._execute("""
                INSERT INTO "AccessLog" (log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (log_id, user_id, file_id, access_attempts, timestamps, ip_address, access_status))
            self.schema.con.commit()
        except Exception:
            self.schema.con.rollback()
            raise

    # Insert file policy information into the database when a user shares a file with another user
    def insert_file_policy(self, policy_id, receiver_id, file_id,
            ip_address, access_count, active_permissions,
            device_verification, location, account_info,
            watermark, data_range, time, biometrics):
        try:
            self._execute("""
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
        except Exception:
            self.schema.con.rollback()
            raise
