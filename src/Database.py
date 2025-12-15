import datetime
import hashlib
import json
import os
import sqlite3

import bcrypt
import pyotp
from argon2 import PasswordHasher
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
    # initiate a new users DB
    def __init__(self):
        self.connection = sqlite3.connect('users.db')
        self.group_seed = GROUP_SEED
        self.create_users_table()
        
    # Creates a new users table
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

    # Creates a new user record in the users table
    def register(self, username, password, salt, hash_mode, metadata='{}', PEPPER= None):    
        with self.connection: 
            # TO DO: implement hashes and crypt modes
            match hash_mode:
                case "TOTP":
                    # TO DO
                    pass
                case "Argon2":
                    # compute Argon2 encrypt + Salt 
                    ph = PasswordHasher()
                    
                    # if PEPPER is added to the hash
                    if PEPPER:
                        password = password + PEPPER
                    
                    hashed_password = ph.hash(password)
                case "bcrypt":
                    salt = bcrypt.gensalt()
                    if PEPPER:
                        password = password + PEPPER
                    # bcrypt hash works with bytes (hence the encode)
                    # decode to make the password more readable (not affecting security)
                    hashed_password = bcrypt.hashpw(password.encode(),salt).decode()

                case "SHA-256 + SALT":
                    password = password+salt
                    # hexdigest to make the password more readable (Hex format)
                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                case "SHA-256 + SALT + PEPPER":
                    if PEPPER == None:
                        print("Requested SHA-256 + SALT + PEPPER mode but PEPPER is empty")
                        raise ValueError(PEPPER)
                    else:
                        # generate a random salt value
                        salt = os.urandom(16)
                        password = password+salt
                        # hexdigest to make the password more readable (Hex format)
                        hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    
            self.connection.execute( 'INSERT INTO users (username, password, salt, hash_mode, group_seed, metadata) VALUES (?, ?, ?, ?, ?, ?)',
            (username, hashed_password, salt, hash_mode, self.group_seed, metadata) )


    # log the login attempt to attempts.log
    def log_attempt(self, logs_info: logs_info, log_file="attempts.log"):
        with open(log_file, "a") as f: 
            f.write(json.dumps(logs_info._asdict()) + "\n")
 
    # login method
    def login(self, username, password_input, PEPPER=None): 
        users = self.get_user(username)

        if users:
            # check each user with the username=<username>
            for user in users:

                match user.hash_mode:
                    case "Argon2":
                        ps = PasswordHasher()
                        if PEPPER:
                            password_input = password_input + PEPPER
                        
                        
                        pass
                    case "bcrypt":
                        pass
                    case "Argon2":
                        pass
                    case "Argon2":
                        pass
                    case "Argon2":
                        pass

                if user.password == password_input:
                    print("user have enter the right password")
                #TO DO:

                # check hash mode

                # compare stored hashed password with hash_mode + password
                pass

    # get user or users by their username value
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