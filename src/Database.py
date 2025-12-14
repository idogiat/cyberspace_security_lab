import datetime
import json
import sqlite3
from typing import NamedTuple

GROUP_SEED = 123456789 # to be corrected


class Line(NamedTuple):
    username: str
    password: str
    salt: str
    hash_mode: str
    group_seed: int
    metadata: str

class logs_info(NamedTuple):
    timestamp: str
    usernmae: str
    groud_seed: str
    hash_mode: str
    protection_flags: str
    result: str
    latency_ms: str


class DB:
    def __init__(self):
        self.connection = sqlite3.connect('users.db')
        self.group_seed = GROUP_SEED
        self.create_users_table()
        

    def create_users_table(self):
        with self.connection:
        
            self.connection.execute("""
                creates a new table users (
                    username TEXT,
                    password TEXT PRIMARY KEY,
                    salt TEXT,
                    hash_mode TEXT,
                    group_seed INTEGER,
                    metadata TEXT         
            )""")

    def register(self, username, password, salt, hash_mode, metadata='{}'):    
        with self.connection: 
            # TO DO: implement hashes and crypt modes
            # match ~ case each mode
            self.connection.execute( 'INSERT INTO users (username, password, salt, hash_mode, group_seed, metadata) VALUES (?, ?, ?, ?, ?, ?)',
            (username, password, salt, hash_mode, self.group_seed, metadata) )

    def log_attempt(self, logs_info: logs_info, log_file="attempts.log"):
        with open(log_file, "a") as f: 
            f.write(json.dumps(logs_info._asdict()) + "\n")
 
            
    def login(self, username, password_input, latency_ms=0, protection_flags=''): 
        users = self.get_user(username)

        if users:
            # check each user with the username=<username>
            for user in users:

                #TO DO:

                # check hash mode

                # compare stored hashed password with hash_mode + password
                pass

     
    def get_user(self, username):
        with self.connection:
            fetchResults = self.conn.execute('SELECT username, password_hash, salt, hash_mode, group_seed, metadata FROM users WHERE username=?', (username,))
            users_records = fetchResults .fetchall()
            
            if users_records:
                users_list = []
                for row in users_records:
                    user = Line(*row)
                    users_list.append(user)
                return users_list
            else:
                return None