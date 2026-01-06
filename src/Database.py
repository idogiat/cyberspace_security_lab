import os
import bcrypt
import hashlib
import sqlite3
import datetime

from typing import NamedTuple
from argon2 import PasswordHasher, exceptions as exceptions_from_argon2

from common import HashingAlgorithm


GROUP_SEED = 524392612  # to be corrected

# convert pepper to bytes to support encrypt functions in the code
PEPPER = os.environ.get("PASSWORD_PEPPER")

class Line(NamedTuple):
    username: str
    password: str
    salt: str
    hash_mode: str
    group_seed: int
    metadata: str
    created_at: str
    totp: str
    pepper: int # 1 for true, 0 for false

class LoginLog(NamedTuple):
    id: int
    username: str
    timestamp: str
    status: str
    ip_address: str
    user_agent: str


class DB:
    def __init__(self, db_path='users.db'):
        """initiate a new users DB"""
        self.db_path = db_path
        self.connection = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self.connection.row_factory = sqlite3.Row
        self.group_seed = GROUP_SEED
        self.create_users_table()
        self.create_login_logs_table()
        
    def create_users_table(self):
        """ Creates a new users table"""
        try:
            with self.connection:
                self.connection.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password TEXT,
                        salt TEXT,
                        hash_mode TEXT,
                        group_seed INTEGER,
                        metadata TEXT,
                        created_at TEXT,
                        totp TEXT,
                        pepper INTEGER                                        
                    )
                """)
                self.connection.commit()
        except Exception as e:
            print(f"Error creating users table: {e}")

    def create_login_logs_table(self):
        """Creates a table for login attempts"""
        try:
            with self.connection:
                self.connection.execute("""
                    CREATE TABLE IF NOT EXISTS login_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        timestamp TEXT,
                        status TEXT,
                        ip_address TEXT,
                        user_agent TEXT
                    )
                """)
                self.connection.commit()
        except Exception as e:
            print(f"Error creating login logs table: {e}")

    # Creates a new user record in the users table
    def register(self, username, password, hash_mode, totp=False, pepper_flag=False, metadata='{}'):  
        try:
            with self.connection:
                salt = ''
                hashed_password = ''

                # Match hash modes and compute appropriate hash
                match hash_mode:
                    case HashingAlgorithm.ARGON2.value:
                        # compute Argon2 encrypt + Salt 
                        ph = PasswordHasher(
                            time_cost=1,
                            memory_cost=65536,  # 64 MB
                            parallelism=1)
                        
                        # if PEPPER is added to the hash
                        if pepper_flag:
                            password = password + PEPPER
                        
                        hashed_password = ph.hash(password)
                    case HashingAlgorithm.BCRYPT.value:
                        # In bcrypt the PEPPER is added to the password instead of to the salt
                        salt = bcrypt.gensalt(rounds=12)
                        if pepper_flag:
                            # bcrypt hash works with bytes (hence the encode)
                            hashed_password = bcrypt.hashpw((password + PEPPER).encode(), salt).decode()
                        else:
                            # decode to make the password more readable (not affecting security)
                            hashed_password = bcrypt.hashpw(password.encode(), salt).decode()

                    case HashingAlgorithm.SHA256_SALT.value:
                        # generate a random salt value
                        salt = os.urandom(16).hex()
                        password = password + salt
                        if pepper_flag:
                            password = password + PEPPER

                        # hexdigest to make the password more readable (Hex format)
                        hashed_password = hashlib.sha256(password.encode()).hexdigest()

                created_at = datetime.datetime.now().isoformat()
                self.connection.execute(
                    'INSERT INTO users (username, password, salt, hash_mode, group_seed, metadata, created_at, totp, pepper) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (username, hashed_password, salt, hash_mode, self.group_seed, metadata, created_at, totp, int(pepper_flag))
                )
                self.connection.commit()
        except sqlite3.IntegrityError:
            print(f"User {username} already exists")
            raise
        except Exception as e:
            print(f"Error registering user: {e}")
            raise

    # log login attempt to database
    def log_login_attempt(self, username, status, ip_address, user_agent):
        """Log login attempt to database"""
        try:
            timestamp = datetime.datetime.now().isoformat()
            with self.connection:
                self.connection.execute("""
                    INSERT INTO login_logs (username, timestamp, status, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, timestamp, status, ip_address, user_agent))
            self.connection.commit()
        except Exception as e:
            print(f"Error logging login attempt: {e}")

    # Get login logs
    def get_login_logs(self, limit=100, username=None):
        """Get login logs from database"""
        try:
            with self.connection:
                if username:
                    cursor = self.connection.execute('''
                        SELECT id, username, timestamp, status, ip_address, user_agent 
                        FROM login_logs 
                        WHERE username = ?
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (username, limit))
                else:
                    cursor = self.connection.execute('''
                        SELECT id, username, timestamp, status, ip_address, user_agent 
                        FROM login_logs 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (limit,))
                
                rows = cursor.fetchall()
                logs = [
                    LoginLog(*row) for row in rows
                ]
                return logs
        except Exception as e:
            print(f"Error retrieving login logs: {e}")
            return []

    # login method
    def login(self, username, password_input): 
        """Authenticate user and return True if successful"""
        try:
            users = self.get_user(username)
            
            
            # no user with the input username
            if not users:
                return False
            
            # check each user with the username=<username>
            for user in users:

                match user.hash_mode:
                    case HashingAlgorithm.ARGON2.value:
                        ph = PasswordHasher(
                            time_cost=1,
                            memory_cost=65536,
                            parallelism=1
                        )   
                        if user.pepper:
                            password_input = password_input + PEPPER
                        try:
                            # ph.verify throws exception if verification failed
                            ph.verify(user.password, password_input)
                            return True
                        except exceptions_from_argon2.VerifyMismatchError:
                            continue
                        
                    case HashingAlgorithm.BCRYPT.value:
                        if user.pepper:
                            password_input = password_input + PEPPER
                        result = bcrypt.checkpw(password_input.encode(), user.password.encode())
                        if result:
                            return True

                    case HashingAlgorithm.SHA256_SALT.value:

                        password_input = password_input + user.salt
                        if user.pepper:
                            password_input = password_input + PEPPER
                        candidate_hash = hashlib.sha256(password_input.encode()).hexdigest()
                        if candidate_hash == user.password:
                            return True

                return False
        except Exception as e:
            print(f"Error during login: {e}")
            return False

    # get user or users by their username value
    def get_user(self, username):
        """Retrieve user from database by username"""
        try:
            with self.connection:
                fetchResults = self.connection.execute(
                    'SELECT username, password, salt, hash_mode, group_seed, metadata, created_at, totp, pepper FROM users WHERE username=?', 
                    (username,)
                )
                users_records = fetchResults.fetchall()
                
                if users_records:
                    users_list = []
                    for row in users_records:
                        user = Line(
                            username=row['username'],
                            password=row['password'],
                            salt=row['salt'],
                            hash_mode=row['hash_mode'],
                            group_seed=row['group_seed'],
                            metadata=row['metadata'],
                            created_at=row['created_at'],
                            totp=row['totp'],
                            pepper=row['pepper']
)
                        users_list.append(user)
                    return users_list
                else:
                    print(f"Did not find a user with username = {username}")
                    return None
        except Exception as e:
            print(f"Error retrieving user: {e}")
            return None

    # Check if user exists
    def user_exists(self, username):
        """Check if user exists in database"""
        try:
            with self.connection:
                cursor = self.connection.execute(
                    'SELECT username FROM users WHERE username=?', 
                    (username,)
                )
                return cursor.fetchone() is not None
        except Exception as e:
            print(f"Error checking if user exists: {e}")
            return False
            
    # for testing purposes
    def delete_all_users(self):
        """Delete all users from database (testing only)"""
        try:
            with self.connection:
                self.connection.execute("DELETE FROM users")
                self.connection.commit()
        except Exception as e:
            print(f"Error deleting users: {e}")

    def delete_all_logs(self):
        """Delete all login logs from database (testing only)"""
        try:
            with self.connection:
                self.connection.execute("DELETE FROM login_logs")
                self.connection.commit()
        except Exception as e:
            print(f"Error deleting logs: {e}")
    
    def get_total_users(self):
        """Get total number of registered users"""
        try:
            with self.connection:
                cursor = self.connection.execute('SELECT COUNT(*) FROM users')
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            print(f"Error getting total users: {e}")
            return 0


def test_db():
    db = DB()
    
    db.delete_all_users()
    db.delete_all_logs()
    print("----- Adding users -----")
    db.register('alice', 'alicepass', 'SHA-256 + SALT')
    db.register('bob', 'bobpass', 'SHA-256 + SALT + PEPPER', "Our PEPPER")
    db.register('charlie', 'charliepass', 'bcrypt')
    db.register('joe', 'joepass', 'Argon2')

    print("----- Login tests -----")
    print("return true if login successful, else return false")
    print("Alice, correct password test: ", db.login('alice', 'alicepass'))  # expect True
    print("Alice, wrong password login test: ", db.login('alice', 'wrong password'))  # expect false
    print("Bob, correct password test :", db.login('bob', 'bobpass', "Our PEPPER"))        # expect True
    print("Bob, wrong password test :", db.login('bob', 'wrong pass', "Our PEPPER"))        #  expect false
    print("Charlie, correct password test :", db.login('charlie', 'charliepass'))# expect True
    print("Charlie, wrong password test :", db.login('charlie', 'wrongpass'))# expect False
    print("joe, correct password test :", db.login('joe', 'joepass'))# expect True
    print("joe, wrong password test :", db.login('joe', 'wrongpass'))# expect False
    
    print("David Not existing user test :", db.login('david', 'nopass'))           # expect false

    print("\n----- Login logs test -----")
    db.log_login_attempt('alice', 'success', '127.0.0.1', 'Mozilla/5.0')
    db.log_login_attempt('bob', 'failed', '192.168.1.1', 'Chrome')
    db.log_login_attempt('charlie', 'success', '10.0.0.1', 'Safari')
    
    logs = db.get_login_logs(limit=5)
    print(f"Total logs retrieved: {len(logs)}")
    for log in logs:
        print(log)

if __name__ == "__main__":
    test_db()  # test DB functions