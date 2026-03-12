import sqlite3 as sql

class Database:
    def __init__(self): 
        self.con = sql.connect("sample.db")
        self.cur = self.con.cursor()

    def run(self):
        self.con.close()
  
if __name__ == "__main__":
    storage = Database()
    storage.run()
