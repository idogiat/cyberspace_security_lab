#!/usr/bin/env python3
"""Generate test users by calling the app's /api/register endpoint and save credentials.

Usage:
    python test_users_generator.py --count 200 --host http://localhost:5000

Notes:
- Run against your local/dev server only.
- This script pauses briefly between requests to avoid bursts; tweak `sleep` as needed.
"""
import requests
import json
import argparse
import time
import random
import string
import pyotp


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
    parser.add_argument("--password", type=str, default="Password1", help="Password for all test users")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between register requests (seconds)")
    parser.add_argument("--random", action='store_true', help="Use randomized usernames to avoid collisions")
    parser.add_argument("--random-length", type=int, default=6, help="Random suffix length when --random is used")
    parser.add_argument("--prefix", type=str, default='loaduser', help="Username prefix")
    parser.add_argument("--max-retries", type=int, default=5, help="Max retries when username exists")
    parser.add_argument("--enable-totp", action='store_true', help="Enable TOTP for generated users")
    parser.add_argument("--output", type=str, default="test_credentials.json", help="Output file for credentials")
    args = parser.parse_args()

    creds = []
    for i in range(args.count):
        username = gen_username(i if not args.random else None, prefix=args.prefix, randomize=args.random, length=args.random_length)
        
        # Generate TOTP secret if enabled
        totp_secret = None
        if args.enable_totp:
            totp_secret = pyotp.random_base32()
        
        payload = {
            "username": username,
            "password": args.password,
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
                cred = {"username": username, "password": args.password}
                if totp_secret:
                    cred["totp_secret"] = totp_secret
                creds.append(cred)

            else:
                print(f"Registration failed for {username}: {r.status_code} {r.text}")

        except Exception as e:
            print('error', e)
            time.sleep(args.delay)
    
    # Save credentials to file
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    print(f"\nCredentials saved to {args.output}")


if __name__ == '__main__':
    generate_users()
