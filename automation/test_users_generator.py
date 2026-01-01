#!/usr/bin/env python3
"""Generate test users by calling the app's /api/register endpoint and save credentials.

Usage:
    python test_users_generator.py --count 200 --host http://localhost:5000
    python test_users_generator.py --dataset weak medium strong --host http://localhost:5000

Notes:
- Run against your local/dev server only.
- Use --dataset to generate users with weak/medium/strong passwords for security testing.
"""
import requests
import json
import argparse
import time
import random
import string
import pyotp
import os
from functools import partial

# Password strength generators for security testing
get_randint = partial(random.randint, 0, 10)


def weak_password_generator() -> str:
    """Generate weak passwords - easily compromised via brute force.
    Examples: 123456, password, qwerty, admin, letmein, etc.
    """
    patterns = [
            f"{get_randint():06d}",  # 000000, 000001, 000002...
            f"pass{get_randint():02d}",  # pass00, pass01...
            f"admin{get_randint()}",  # admin0, admin1...
            f"user{get_randint():02d}",  # user00, user01...
            f"123{get_randint():03d}",  # 12300, 12301...
            f"pwd{get_randint():04d}",  # pwd0000, pwd0001...
            f"test{get_randint():02d}",  # test00, test01...
            f"abcd{get_randint():02d}",  # abcd00, abcd01...
            f"guest{get_randint()}",  # guest0, guest1...
        ]
    return random.choice(patterns)
    

def medium_password_generator():
    """Generate medium strength passwords - moderate complexity.
    Mix of uppercase, lowercase, numbers, occasional special chars.
    """
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    days = ['01', '15', '31', '05', '20', '10', '25', '30', '12', '07']
    patterns = [
        f"Pass{get_randint():02d}Word",  # Pass00Word, Pass01Word...
        f"Secure{get_randint():03d}",  # Secure000, Secure001...
        f"User{2020 + (get_randint() % 5)}",  # User2020, User2021...
        f"{months[get_randint() % 12]}Pass{get_randint():02d}",  # JanPass00, FebPass01...
        f"Demo{get_randint():02d}@Test",  # Demo00@Test, Demo01@Test...
        f"Key{get_randint():04d}Code",  # Key0000Code, Key0001Code...
        f"Admin{days[get_randint() % 10]}",  # Admin01, Admin15...
        f"Login{get_randint():02d}$",  # Login00$, Login01$...
        f"Access{get_randint():03d}Key",  # Access000Key, Access001Key...
        f"Data{2024 - (get_randint() % 5)}{chr(65 + (get_randint() % 26))}",  # Data2024A, Data2023B...
    ]
    
    return random.choice(patterns)


def strong_password_generator():
    """Generate strong passwords - high complexity with special chars, mixed case.
    Multiple special chars, numbers in different positions, long length.
    """
    special_chars = ['!', '@', '#', '$', '%', '&', '*', '+', '-', '=']
    patterns = [
        f"C0mp{special_chars[get_randint() % len(special_chars)]}Secure{get_randint():03d}{special_chars[(get_randint() + 1) % len(special_chars)]}Key",
        f"{special_chars[get_randint() % len(special_chars)]}MyP@ssw0rd{get_randint():04d}{special_chars[(get_randint() + 2) % len(special_chars)]}",
        f"P@ss{chr(65 + (get_randint() % 26))}{get_randint():05d}{special_chars[(get_randint() + 3) % len(special_chars)]}Secure",
        f"Str0ng{special_chars[get_randint() % len(special_chars)]}{chr(97 + (get_randint() % 26))}{get_randint():04d}{special_chars[(get_randint() + 1) % len(special_chars)]}",
        f"{get_randint():03d}Key{special_chars[get_randint() % len(special_chars)]}{chr(65 + ((get_randint() + 5) % 26))}{special_chars[(get_randint() + 2) % len(special_chars)]}Pwd",
        f"Adv@nced{special_chars[(get_randint() + 1) % len(special_chars)]}{get_randint():05d}{chr(97 + ((get_randint() + 10) % 26))}{special_chars[get_randint() % len(special_chars)]}",
        f"C{special_chars[get_randint() % len(special_chars)]}mpl3x{get_randint():04d}{special_chars[(get_randint() + 2) % len(special_chars)]}{chr(65 + (get_randint() % 26))}S3cur3",
        f"M@ster{chr(97 + (get_randint() % 26))}{get_randint():04d}{special_chars[get_randint() % len(special_chars)]}{special_chars[(get_randint() + 1) % len(special_chars)]}Key",
        f"R0bUst{special_chars[(get_randint() + 3) % len(special_chars)]}{get_randint():05d}{chr(65 + ((get_randint() + 7) % 26))}{special_chars[get_randint() % len(special_chars)]}",
        f"{special_chars[get_randint() % len(special_chars)]}P@ssP{chr(65 + (get_randint() % 26))}{get_randint():05d}{special_chars[(get_randint() + 1) % len(special_chars)]}{chr(97 + ((get_randint() + 12) % 26))}",
    ]
    return random.choice(patterns)

def gen_username(i=None, prefix='loaduser', randomize=False, length=6):
    """Generate a username. If randomize=True, create a random suffix; otherwise use numeric index."""
    if randomize:
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return f"{prefix}_{suffix}"
    else:
        return f"{prefix}{i}"


def generate_users():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=10, help="Number of test users to create")
    parser.add_argument("--host", type=str, default="http://localhost:5000", help="Server base URL")
    parser.add_argument("--password", type=str, default=None, help="Password for all test users (overrides --dataset)")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between register requests (seconds)")
    parser.add_argument("--random", action='store_true', help="Use randomized usernames to avoid collisions")
    parser.add_argument("--random-length", type=int, default=6, help="Random suffix length when --random is used")
    parser.add_argument("--prefix", type=str, default='loaduser', help="Username prefix")
    parser.add_argument("--max-retries", type=int, default=5, help="Max retries when username exists")
    parser.add_argument("--enable-totp", action='store_true', help="Enable TOTP for generated users")
    parser.add_argument("--output", type=str, default="test_credentials.json", help="Output file for credentials")
    parser.add_argument("--type", type=str, help="Create user with passwort type weak/medium/strong passwords (e.g. weak medium strong)")
    args = parser.parse_args()

    creds = []
    user_count = 0
    
    # If dataset mode, generate 10 users per category
    if args.type:
        print(f"Dataset mode: Creating {args.type} passwords for {args.count} users")
        for i in range(args.count):
            if args.type == 'weak':
                password_gen = weak_password_generator()
            elif args.type == 'medium':
                password_gen = medium_password_generator()
            elif args.type == 'strong':
                password_gen = strong_password_generator()
            else:
                print(f"Unknown password type: {args.type}")
                continue
            
            username = f"{args.prefix}_{args.type}_{i}"
                
            totp_secret = ''
            if args.enable_totp:
                totp_secret = pyotp.random_base32()
            
            payload = {
                "username": username,
                "password": password_gen,
                "hash_mode": "bcrypt",
                "use_totp": args.enable_totp
            }
            
            if totp_secret:
                payload["totp_secret"] = totp_secret
            
            try:
                r = requests.post(f"{args.host}/api/register", json=payload, timeout=10)
                status = r.status_code
                print(f"attempt {user_count+1} -> {username} ({args.type}) -> {status}")
                if status in (200, 201):
                    cred = {"username": username, "password": password_gen, "strength": args.type}
                    if totp_secret:
                        cred["totp_secret"] = totp_secret
                    creds.append(cred)
                    user_count += 1
                else:
                    print(f"  Registration failed: {r.status_code} {r.text}")
            
            except Exception as e:
                print(f'  error: {e}')
                time.sleep(args.delay)
    else:
        # Original mode: use single password for all users
        password = args.password or "Password1"
        for i in range(args.count):
            username = gen_username(i if not args.random else None, prefix=args.prefix, randomize=args.random, length=args.random_length)
            
            # Generate TOTP secret if enabled
            totp_secret = ''
            if args.enable_totp:
                totp_secret = pyotp.random_base32()
            
            payload = {
                "username": username,
                "password": password,
                "hash_mode": "bcrypt",
                "use_totp": args.enable_totp
            }
            
            if totp_secret:
                payload["totp_secret"] = totp_secret
            
            try:
                r = requests.post(f"{args.host}/api/register", json=payload, timeout=10)
                status = r.status_code
                print(f"attempt {i+1} -> {username} -> {status}")
                if status in (200, 201):
                    cred = {"username": username, "password": password}
                    if totp_secret:
                        cred["totp_secret"] = totp_secret
                    creds.append(cred)

                else:
                    print(f"Registration failed for {username}: {r.status_code} {r.text}")

            except Exception as e:
                print('error', e)
                time.sleep(args.delay)
    
    # Save credentials to file
    exists_users = []
    if os.path.exists(args.output):
        with open(args.output, 'r', encoding='utf-8') as f:
            exists_users = json.load(f)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(exists_users + creds, f, indent=4, ensure_ascii=False)
    print(f"\n✓ Credentials saved to {args.output} ({len(creds)} users)")


if __name__ == '__main__':
    generate_users()
