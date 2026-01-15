#!/usr/bin/env python3
"""
Generate test users by calling the app's /api/register endpoint and save credentials.
Also generates finite password wordlists for demo brute-force attacks.
"""

import os
import json
import time
import pyotp
import random
import string
import requests
import argparse
from pathlib import Path

from src.common import ServerStatus, HashingAlgorithm

# =========================
# CONSTANTS
# =========================

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '../src/config.json')
with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.load(f)
HASH_MODE = CONFIG.get('USERS_HASH_MODE', 1)
TOTP_ACTIVATED = CONFIG.get("USERS_TOTP", False)
PEPPER_ACTIVATED = CONFIG.get("USERS_PEPPER", False)

MAX_WEAK   = 5_000
MAX_MEDIUM = 7_000
MAX_STRONG = 15_000
PASS_SPRAYING = 1_667

BASE_DIR = Path(os.path.dirname(__file__))

WEAK_FILE   = BASE_DIR / "passwords_weak.txt"
MEDIUM_FILE = BASE_DIR / "passwords_medium.txt"
STRONG_FILE = BASE_DIR / "passwords_strong.txt"

SPECIALS = ["!", "@", "#", "$", "%"]

# =========================
# PASSWORD LIST GENERATORS
# =========================

def generate_weak_list():
    """
    VERY weak – looks like real bad human passwords.
    """
    common = [
        "123456", "111111", "123123", "password", "password1",
        "qwerty", "qwerty123", "admin", "admin123",
        "welcome", "letmein", "iloveyou", "pass123"
    ]

    pwds = set(common)

    bases = ["pass", "admin", "test", "user", "login"]
    while len(pwds) < MAX_WEAK:
        base = random.choice(bases)
        num = random.randint(0, 999)
        pwds.add(f"{base}{num}")
        pwds.add(f"{base.capitalize()}{num}")

    return list(pwds)


def generate_medium_list():
    """
    Medium – reasonable, common patterns people believe are strong.
    Letters + numbers, sometimes mixed case, no real entropy.
    """
    words = [
        "Sun", "Moon", "Fire", "Stone", "Sky",
        "River", "Shadow", "Light", "Iron", "Wolf"
    ]

    pwds = set()

    while len(pwds) < MAX_MEDIUM:
        w = random.choice(words)
        num = random.randint(10, 9999)

        pwds.add(f"{w}{num}")
        pwds.add(f"{w.lower()}{num}")
        pwds.add(f"{w}{num}A")
        pwds.add(f"{w.capitalize()}{num}Z")

    return list(pwds)


def generate_strong_list():
    """
    Strong – looks truly random, but finite and crackable.
    """
    pwds = set()

    alphabet = string.ascii_letters + string.digits + "".join(SPECIALS)

    while len(pwds) < MAX_STRONG:
        length = random.randint(10, 14)
        pwd = "".join(random.choice(alphabet) for _ in range(length))

        # enforce at least: lower, upper, digit, special
        if (
            any(c.islower() for c in pwd) and
            any(c.isupper() for c in pwd) and
            any(c.isdigit() for c in pwd) and
            any(c in SPECIALS for c in pwd)
        ):
            pwds.add(pwd)

    return list(pwds)


# =========================
# LOAD OR GENERATE LISTS
# =========================

def load_or_generate(path: Path, generator):
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]

    pwds = generator()
    with open(path, "w", encoding="utf-8") as f:
        for p in pwds:
            f.write(p + "\n")
    return pwds


WEAK_PASSWORDS   = load_or_generate(WEAK_FILE, generate_weak_list)
MEDIUM_PASSWORDS = load_or_generate(MEDIUM_FILE, generate_medium_list)
STRONG_PASSWORDS = load_or_generate(STRONG_FILE, generate_strong_list)

# =========================
# PASSWORD PICKERS
# =========================

def weak_password_generator():
    return random.choice(WEAK_PASSWORDS)

def medium_password_generator():
    return random.choice(MEDIUM_PASSWORDS)

def strong_password_generator():
    return random.choice(STRONG_PASSWORDS)

# =========================
# USERNAME GENERATOR (UNCHANGED)
# =========================

def gen_username(i=None, prefix='loaduser', randomize=False, length=6):
    if randomize:
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return f"{prefix}_{suffix}"
    return f"{prefix}{i}"


def generate_combined_passwords(out_file="combined_passwords.txt"):
    with open(WEAK_FILE, encoding="utf-8") as f:
        weak_pwds = [line.strip() for line in f if line.strip()]
    with open(MEDIUM_FILE, encoding="utf-8") as f:
        medium_pwds = [line.strip() for line in f if line.strip()]
    with open(STRONG_FILE, encoding="utf-8") as f:
        strong_pwds = [line.strip() for line in f if line.strip()]

    weak_part = random.sample(weak_pwds, PASS_SPRAYING)
    medium_part = random.sample(medium_pwds, PASS_SPRAYING)
    strong_part = random.sample(strong_pwds, PASS_SPRAYING)

    all_pwds = weak_part + medium_part + strong_part
    random.shuffle(all_pwds)
    passwords = "\n".join(list(all_pwds))
    
    outpath = BASE_DIR / out_file
    with open(outpath, "w") as f:
        for p in all_pwds:
            f.write(passwords)
    print(f"Combined password file written to: {outpath}")



# =========================
# MAIN FLOW (UNCHANGED)
# =========================

def generate_users():
    parser = argparse.ArgumentParser()

    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--host", type=str, default="http://localhost:5000")
    parser.add_argument("--password", type=str, default=None)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--random", action='store_true')
    parser.add_argument("--random-length", type=int, default=6)
    parser.add_argument("--prefix", type=str, default='loaduser')
    parser.add_argument("--max-retries", type=int, default=5)
    parser.add_argument("--enable-totp", action='store_true')
    parser.add_argument("--output", type=str, default="test_credentials.json")
    parser.add_argument("--type", type=str)
    parser.add_argument("--password_spraying", action='store_true')

    args = parser.parse_args()

    if args.password_spraying:
        generate_combined_passwords()
        exit(0)

    creds = []
    counter = 1
    use_pepper = False

    print(f"Creating {args.count} users of type {args.type}")

    while counter <= args.count:
        if args.password:
            password = args.password
        elif args.type == "weak":
            password = weak_password_generator()
            use_pepper = False
        elif args.type == "medium":
            password = medium_password_generator()
            use_pepper ^= True
        elif args.type == "strong":
            password = strong_password_generator()
            use_pepper = True
        else:
            print("Unknown password type")
            return

        username = f"{args.prefix}_{args.type}_{counter}"
        args.enable_totp = TOTP_ACTIVATED
        totp_secret = pyotp.random_base32() if args.enable_totp else None
        hash_mode = list(HashingAlgorithm)[HASH_MODE].value
        if use_pepper == True and PEPPER_ACTIVATED == False:
            use_pepper = False
        payload = {
            "username": username,
            "password": password,
            "hash_mode": hash_mode,
            "use_totp": args.enable_totp,
            "use_pepper": use_pepper
        }

        if totp_secret:
            payload["totp_secret"] = totp_secret

        try:
            r = requests.post(f"{args.host}/api/register", json=payload, timeout=10)
            print(f"attempt {counter} -> {username} -> {r.status_code}")

            if r.status_code in (ServerStatus.OK.value, ServerStatus.CREATED.value):
                entry = {"username": username, "password": password, "strength": args.type}
                if totp_secret:
                    entry["totp_secret"] = totp_secret
                creds.append(entry)
                counter += 1
            elif r.status_code == ServerStatus.CONFLICT.value:
                counter += 1
                args.count += 1
            else:
                print(f"Registration failed: {r.text}")

        except Exception as e:
            print(f"error: {e}")
            time.sleep(args.delay)

    existing = []
    if os.path.exists(args.output):
        with open(args.output, "r", encoding="utf-8") as f:
            existing = json.load(f)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(existing + creds, f, indent=4)

    print(f"Saved {len(creds)} users to {args.output}")

if __name__ == "__main__":
    generate_users()