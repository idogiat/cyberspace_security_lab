import pandas
import requests
import json
import time
import os
import psutil
import threading

from typing import List
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


class PASSWORDSPRAYSIMULATOR():
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

        self.total_cpu = 0.0
        self.total_mem = 0.0
        self.avg_cpu = 0.0
        self.avg_mem = 0.0

        self.users = self._load_users()
        self.num_users = len(self.users)
        self.passwords = self._load_passwords()

        self.start_time = time.time()
        self.total_attempts = 0
        self.time_to_first_success = None
        self.global_latency = 0
        self.num_cracked = 0

        self.global_lock = threading.Lock()
        self.user_locks = {u: threading.Lock() for u in self.users}

        self.summary = {
            "users": {},
            "by_category": defaultdict(list),
            "cpu": [],
            "mem": [],
            "start_time": self.start_time
        }

        self.user_stats = {
            user: {
                'attempts': 0,
                'category': None,
                'cracked': False,
                'password_found': None,
                'time_to_success': None,
                'totp_stopped': False,
                'latency_sum': 0.0,
                'last_latency': None,
                'absolute_first_success': None,
                'cpu_sum': 0.0,
                'cpu_count': 0,
                'mem_sum': 0.0,
                'mem_count': 0,
            }
            for user in self.users
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

    # ---------- Helpers ----------

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
        r = requests.get(
            self.CAPTCHA_TOKEN_URL,
            params={"group_seed": self.GROUP_SEED, "username": username}
        )
        return r.json().get("captcha_token")

    # ---------- Core Logic ----------

    def attempt_login(self, payload: dict) -> tuple[dict, float, int]:
        t0 = time.time()
        r = requests.post(self.SERVER_URL, json=payload, timeout=5)
        latency = (time.time() - t0) * 1000
        try:
            return r.json(), latency, r.status_code
        except Exception:
            return {}, latency, r.status_code

    def _spray_single_user(self, username: str, password: str):
        print(f"[*] Trying {username} with password: {password}")

        latency = 0.0
        user_start = time.time()

        with self.user_locks[username]:
            user_stats = self.user_stats[username]

            try:
                if user_stats['cracked'] or user_stats['totp_stopped']:
                    return

                if self._should_stop():
                    return

                category = self.get_category(username)
                user_stats['category'] = category

                payload = {"username": username, "password": password}
                resp, latency, status = self.attempt_login(payload)

                if resp.get("captcha_required"):
                    payload["captcha_token"] = self.handle_captcha(username)
                    resp, latency, status = self.attempt_login(payload)

                if status == 423 or "permanently locked" in resp.get("message", "").lower():
                    print(f"[!] User {username} permanently locked")
                    return

                if self.is_totp_required(resp):
                    self._mark_success(user_stats, password, user_start, totp=True)
                    print(f"[!] User {username} blocked by TOTP")
                    return

                if resp.get("success"):
                    self._mark_success(user_stats, password, user_start)
                    print(f"[+] User {username} cracked! Password: {password}")
                    return

                if user_stats["attempts"] >= self.MAX_ATTEMPTS_PER_USER:
                    return

                self.summary["users"][username] = user_stats
                self.summary["by_category"][category].append(user_stats)

            finally:
                self._record_attempt(user_stats, latency)

    def passwory_spray(self, password: str):
        with ThreadPoolExecutor(max_workers=len(self.users)) as executor:
            futures = [
                executor.submit(self._spray_single_user, username, password)
                for username in self.users
            ]
            for _ in as_completed(futures):
                if self._should_stop():
                    break

    # ---------- State Management ----------

    def _record_attempt(self, user_stats, latency):
        with self.global_lock:
            self.total_attempts += 1
            user_stats["attempts"] += 1
            user_stats["latency_sum"] += latency
            user_stats["last_latency"] = latency

            cpu_now = psutil.cpu_percent()
            mem_now = psutil.virtual_memory().percent

            user_stats["cpu_sum"] += cpu_now
            user_stats["cpu_count"] += 1
            user_stats["mem_sum"] += mem_now
            user_stats["mem_count"] += 1

            self.global_latency += latency

    def _mark_success(self, user_stats, password, start, totp=False):
        user_stats["cracked"] = True
        user_stats["password_found"] = password
        user_stats["time_to_success"] = time.time() - start
        user_stats["absolute_first_success"] = time.time()
        user_stats["totp_stopped"] = totp

        if not totp:
            self.num_cracked += 1
            if self.time_to_first_success is None:
                self.time_to_first_success = user_stats["time_to_success"]

    def _should_stop(self) -> bool:
        return (
            time.time() - self.start_time > self.MAX_RUNTIME or
            self.total_attempts >= self.MAX_TOTAL_ATTEMPTS
        )

    # ---------- Execution ----------

    def run(self):
        start_time = time.time()

        for password in self.passwords:
            print(f"\n[password spray with password: {password}]")
            self.passwory_spray(password)

            if time.time() - start_time > self.MAX_RUNTIME:
                print("[!!!] Spraying stopped - time limit reached")
                break

        self._finalize()
        self.print_summary()

    def _finalize(self):
        self.cracked_per_cat = defaultdict(int)
        self.totp_per_cat = defaultdict(int)
        self.summary["by_category"] = defaultdict(list)

        cpu_vals = []
        mem_vals = []

        for username, us in self.user_stats.items():
            cat = self.get_category(username)

            self.total_cpu += us["cpu_sum"]
            self.total_mem += us["mem_sum"]

            if us['cracked'] and not us['totp_stopped']:
                self.cracked_per_cat[cat] += 1
            if us['totp_stopped']:
                self.totp_per_cat[cat] += 1

            self.summary["by_category"][cat].append(us)

            if us["cpu_count"]:
                cpu_vals.append(us["cpu_sum"] / us["cpu_count"])
            if us["mem_count"]:
                mem_vals.append(us["mem_sum"] / us["mem_count"])
            
        self.avg_cpu = sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0
        self.avg_mem = sum(mem_vals) / len(mem_vals) if mem_vals else 0

    # ---------- Reporting ----------

    def print_summary(self):
        summary_data = []
        duration = time.time() - self.start_time

        print("\n========== SUMMARY ==========")

        total_totp_blocked = 0
        for cat in ["weak", "medium", "strong"]:
            users = self.summary["by_category"][cat]
            cracked = sum(1 for u in users if u["cracked"] and not u["totp_stopped"])
            totp = sum(1 for u in users if u["totp_stopped"])

            print(f"{cat}: cracked={cracked}, totp_blocked={totp}, total={len(users)}")

            total_totp_blocked += totp
            summary_data.append({
                "Category": cat,
                "Cracked": cracked,
                "TOTP Blocked": totp,
                "Total": len(users)
            })

        print(f"\nTotal attempts: {self.total_attempts}")
        print(f"Attempts/sec: {self.total_attempts / duration:.2f}")
        print(f"Avg CPU: {self.avg_cpu}%")
        print(f"Avg RAM: {self.avg_mem}%")

        success_rate = self.num_cracked / self.num_users * 100 if self.num_users else 0
        print(f"Success rate: {success_rate:.2f}%")

        summary_row = {
            "attack duration": duration,
            "Total attempts": self.total_attempts,
            "Total successes": self.num_cracked,
            "Total TOTP blocked": total_totp_blocked,
            "Attempts per second": self.total_attempts / duration if duration > 0 else 0,
            "Time to first success": self.time_to_first_success if self.time_to_first_success else None,
            "Success rate (%)": self.num_cracked / self.num_users * 100 if self.num_users else 0,
            "Avg latency (ms)": (self.global_latency / self.total_attempts) if self.global_latency else None,
            "Avg CPU (%)": self.avg_cpu,
            "Avg RAM (%)": self.avg_mem
        }


        df = pandas.DataFrame(summary_data)
        total_df = pandas.DataFrame([summary_row])
        with open("password_spray_summary.csv", "a", encoding="utf-8", newline="") as f:
            f.write("\n\n ::: password_spray_summary ::: \n")  
            now = time.strftime("run ended at  %H:%M %d/%m/%Y\n")
            f.write(now)  
            df.to_csv(f, index=False, header=True)
            f.write("\n\n")  
            f.write("Totals\n") 
            total_df.to_csv(f, index=False, header=True)
        print("[✓] password_spray_summary.csv written!")


if __name__ == "__main__":
    user_path = os.path.join(os.path.dirname(__file__), "../src/users.json")
    passwords_path = os.path.join(os.path.dirname(__file__), "./combined_passwords.txt")

    sim = PASSWORDSPRAYSIMULATOR(user_path, passwords_path)
    sim.run()
