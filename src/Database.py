import datetime
import hashlib
import json
import os
import sqlite3

import bcrypt
import pyotp
from argon2 import PasswordHasher, exceptions as exceptions_from_argon2
from typing import NamedTuple


GROUP_SEED = 123456789 # to be corrected


class Line(NamedTuple):
    username: str
    password: str
    salt: str
    hash_mode: str
    group_seed: int
    metadata: str

class LogsInfo(NamedTuple):
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
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT,
                    password TEXT,
                    salt TEXT,
                    hash_mode TEXT,
                    group_seed INTEGER,
                    metadata TEXT         
            )""")

    # Creates a new user record in the users table
    def register(self, username, password, hash_mode, PEPPER= None, metadata='{}'):    
        with self.connection: 
            salt = ''
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
                    # generate a random salt value
                    salt = os.urandom(16).hex()
                    password = password + salt
                    # hexdigest to make the password more readable (Hex format)
                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                case "SHA-256 + SALT + PEPPER":
                    if PEPPER == None:
                        print("Requested SHA-256 + SALT + PEPPER mode but PEPPER was not provided")
                        raise ValueError(PEPPER)
                    else:
                        # generate a random salt value
                        salt = os.urandom(16).hex()
                        password = password+salt
                        # hexdigest to make the password more readable (Hex format)
                        hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    
            self.connection.execute( 'INSERT INTO users (username, password, salt, hash_mode, group_seed, metadata) VALUES (?, ?, ?, ?, ?, ?)',
            (username, hashed_password, salt, hash_mode, self.group_seed, metadata) )


    # log the login attempt to attempts.log
    def log_attempt(self, logs_info: LogsInfo, log_file="attempts.log"):
        with open(log_file, "a") as f: 
            f.write(json.dumps(logs_info._asdict()) + "\n")
 

    # login method
    def login(self, username, password_input, PEPPER=None): 
        users = self.get_user(username)
        
        # no user with the input usernmae
        if not users:
            return False
        # check each user with the username=<username>
        for user in users:

            match user.hash_mode:
                case "Argon2":
                    ph = PasswordHasher()
                    if PEPPER:
                        password_input = password_input + PEPPER
                    try:
                        # ph.verify throws exception if verification failed
                        ph.verify(user.password,password_input)
                        return True
                    except exceptions_from_argon2.VerifyMismatchError:
                        continue
                    
                case "bcrypt":
                    if PEPPER:
                        password_input = password_input + PEPPER
                    result = bcrypt.checkpw(password_input.encode(), user.password.encode())
                    if result:
                        return True

                    pass
                case "SHA-256 + SALT":
                    password_input = password_input + user.salt
                    candidate_hash = hashlib.sha256(password_input.encode()).hexdigest()

                    if candidate_hash == user.password:
                        return True
                    

                    pass
                case "SHA-256 + SALT + PEPPER":
                    if not PEPPER:
                        print("Requested SHA-256 + SALT + PEPPER mode but PEPPER was not provided")
                    password_input = password_input + user.salt + PEPPER
                    candidate_hash = hashlib.sha256(password_input.encode()).hexdigest()

                    if candidate_hash == user.password:
                        return True
                    pass
                case "TOTP":
                    # TO DO
                    pass
            
            # print("can't verify user with username = " +user.username + "and with password = " + password_input)
            return False
            

    # get user or users by their username value
    def get_user(self, username):
        with self.connection:
            fetchResults = self.connection.execute('SELECT username, password, salt, hash_mode, group_seed, metadata FROM users WHERE username=?', (username,))
            users_records = fetchResults .fetchall()
            
            if users_records:
                users_list = []
                for row in users_records:
                    user = Line(*row)
                    users_list.append(user)
                    
                return users_list
            else:
                print("did not found a user with usernaame = " + username)
                return None
            
    # for testing purposes
    def delete_all_users(self):
        with self.connection:
            self.connection.execute("DELETE FROM users")
            



def test_db():
    # יצירת אובייקט של DB (בהנחה שמימוש המחלקה תקין)
    db = DB()
    
    db.delete_all_users()
    print("----- Adding users -----")
    db.register('alice', 'alicepass', 'SHA-256 + SALT')
    db.register('bob', 'bobpass', 'SHA-256 + SALT + PEPPER',"Our PEPPER")
    db.register('charlie', 'charliepass', 'bcrypt')
    db.register('joe', 'joepass', 'Argon2')

    print("----- Login tests -----")
    print("return true if login succesful, else return false")
    print("Alice, correct password test: ", db.login('alice', 'alicepass'))  # expect True
    print("Alice, wrong password login test: ", db.login('alice', 'wrong password'))  # expect false
    print("Bob, correct password test :", db.login('bob', 'bobpass',"Our PEPPER"))        # expect True
    print("Bob, wrong password test :", db.login('bob', 'wrong pass',"Our PEPPER"))        #  expect false
    print("Charlie, correct password test :", db.login('charlie', 'charliepass'))# expect True
    print("Charlie, wrong password test :", db.login('charlie', 'wrongpass'))# expect False
    print("joe, correct password test :", db.login('joe', 'joepass'))# expect True
    print("joe, wrong password test :", db.login('joe', 'wrongpass'))# expect False
    
    
    print("David Not existing user test :", db.login('david', 'nopass'))           # expect false




if __name__ == "__main__":
    test_db()  # test DB funcitons