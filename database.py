import sqlite3 as sql

class Database:
    def __init__(self): 
        self.con = sql.connect("sample.db")
        self.cur = self.con.cursor()
        
    def create_user_table(self):
        self.cur.execute("""CREATE TABLE IF NOT EXISTS User(
                         user_id TEXT PRIMARY KEY,
                         username TEXT NOT NULL UNIQUE,
                         password TEXT NOT NULL,
                         tag_id TEXT)
                         """)  
        
    def run(self):
        self.create_user_table
        self.con.commit()
        self.con.close()
  
if __name__ == "__main__":
    storage = Database()
    storage.run()
