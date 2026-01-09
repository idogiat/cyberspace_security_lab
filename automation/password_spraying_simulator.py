import requests
import json
import time
import os
import psutil
from typing import List
from collections import defaultdict


class BruteForceSimulator():
    SERVER_URL = 'http://localhost:5000/api/login'
    CAPTCHA_TOKEN_URL = 'http://localhost:5000/admin/get_captcha_token'
    GROUP_SEED = 524392612
    MAX_ATTEMPTS_PER_USER = 50_000
    MAX_TOTAL_ATTEMPTS = 1_000_000
    MAX_RUNTIME = 2 * 60 * 60  # 2 hours

    def __init__(self, users_file: str, passwords_file: str):
        """        
        Parameters:
            users_file (str): Path to the users.json file
            passwords_file (str): Path to the common passwords file
        """
        self.users_file = users_file
        self.passwords_file = passwords_file

        self.users = self._load_users()
        self.passwords = self._load_passwords()
        self.start_time = time.time()
        self.total_attempts = 0
        self.summary = {
            "users": {},
            "by_category": defaultdict(list),
            "cpu": [],
            "mem": [],
            "start_time": self.start_time
        }

    # ---------- Loaders ----------

    def _load_users(self) -> List[str]:
        """
        Load users from users.json file into usernames array

        Returns:
            List[str]: List of usernames
        """
        with open(self.users_file, "r") as f:
            data = json.load(f)
        return [u["username"] if isinstance(u, dict) else u for u in data.get("users", [])]

    def _load_passwords(self) -> List[str]:
        with open(self.passwords_file, "r") as f:
            return [line.strip() for line in f if line.strip()]

    # ---------- Helpers ---------- #

    @staticmethod
    def get_category(username: str) -> str:
        if 'weak' in username:
            return 'weak'
        if 'medium' in username:
            return 'medium'
        if 'strong' in username:
            return 'strong'
        return 'other'

    @staticmethod
    def is_totp_required(resp: dict) -> bool:
        return (
            resp.get("success") and
            "totp required" in resp.get("message", "").lower() and
            resp.get("redirect") == "/totp-verify"
        )

    def handle_captcha(self, username: str) -> str:
        r = requests.get('http://localhost:5000/admin/get_captcha_token', params={"group_seed": self.GROUP_SEED, "username": username})
        return r.json().get("captcha_token")

    # ---------- Core Logic ---------- #

    def attempt_login(self, payload: dict) -> tuple[dict, float, int]:
        t0 = time.time()
        r = requests.post(self.SERVER_URL, json=payload, timeout=5)
        latency = (time.time() - t0) * 1000
        try:
            return r.json(), latency, r.status_code
        except Exception:
            return {}, latency, r.status_code

    def attack_user(self, username: str):
        category = self.get_category(username)
        user_stats = {
            "attempts": 0,
            "cracked": False,
            "password_found": None,
            "time_to_success": None,
            "latencies": [],
            "totp_stopped": False
        }

        user_start = time.time()
        for password in self.passwords:
            if self._should_stop():
                break

            payload = {"username": username, "password": password}
            resp, latency, status = self.attempt_login(payload)
            self._record_attempt(user_stats, latency)

            # CAPTCHA
            if resp.get("captcha_required"):
                while True:
                    payload["captcha_token"] = self.handle_captcha(username)
                    resp, latency, status = self.attempt_login(payload)
                    self._record_attempt(user_stats, latency)
                    if resp.get("message") != "Invalid CAPTCHA token":
                        break
                    

            # Permanent lock
            if status == 423 or "permanently locked" in resp.get("message", "").lower():
                print(f"[!] User {username} permanently locked after {user_stats['attempts']} attempts")
                break

            # TOTP success
            if self.is_totp_required(resp):
                self._mark_success(user_stats, password, user_start, totp=True)
                print(f"[!] User {username} blocked by TOTP requirement after {user_stats['attempts']} attempts")
                break

            # Full success
            if resp.get("success"):
                self._mark_success(user_stats, password, user_start)
                print(f"[+] User {username} cracked! Password: {password}") 
                break

            if user_stats["attempts"] >= self.MAX_ATTEMPTS_PER_USER:
                break

        self.summary["users"][username] = user_stats
        self.summary["by_category"][category].append(user_stats)

    # ---------- State Management ---------- #

    def _record_attempt(self, user_stats, latency):
        self.total_attempts += 1
        user_stats["attempts"] += 1
        user_stats["latencies"].append(latency)
        self.summary["cpu"].append(psutil.cpu_percent())
        self.summary["mem"].append(psutil.virtual_memory().percent)

    def _mark_success(self, user_stats, password, start, totp=False):
        user_stats["cracked"] = True
        user_stats["password_found"] = password
        user_stats["time_to_success"] = time.time() - start
        user_stats["totp_stopped"] = totp

    def _should_stop(self) -> bool:
        return (time.time() - self.start_time > self.MAX_RUNTIME or self.total_attempts >= self.MAX_TOTAL_ATTEMPTS)

    # ---------- Execution ---------- #

    def run(self):
        for user in self.users:
            print(f"\n[Attacking {user}]")
            self.attack_user(user)

        self.print_summary()

    # ---------- Reporting ----------#

    def print_summary(self):
        duration = time.time() - self.start_time
        print("\n========== SUMMARY ==========")

        for cat in ["weak", "medium", "strong"]:
            users = self.summary["by_category"][cat]
            cracked = sum(1 for u in users if u["cracked"] and not u["totp_stopped"])
            totp = sum(1 for u in users if u["totp_stopped"])
            print(f"{cat}: cracked={cracked}, totp_blocked={totp}, total={len(users)}")

        print(f"\nTotal attempts: {self.total_attempts}")
        print(f"Attempts/sec: {self.total_attempts / duration:.2f}")
        print(f"Avg CPU: {sum(self.summary['cpu'])/len(self.summary['cpu']):.1f}%")
        print(f"Avg RAM: {sum(self.summary['mem'])/len(self.summary['mem']):.1f}%")


if __name__ == "__main__":
    user_path = os.path.join(os.path.dirname(__file__), "../src/users.json")
    passwords_path = os.path.join(os.path.dirname(__file__), "../small_password_register.txt")
    sim = BruteForceSimulator(users_file=user_path, passwords_file=passwords_path)
    sim.run()