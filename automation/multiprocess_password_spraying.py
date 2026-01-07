import requests
import json
import time
import os
import psutil
import threading
from typing import List
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from copy import deepcopy



class BruteForceSimulator:
    SERVER_URL = 'http://localhost:5000/api/login'
    GROUP_SEED = 524392612
    MAX_ATTEMPTS_PER_USER = 50_000
    MAX_TOTAL_ATTEMPTS = 1_000_000
    MAX_RUNTIME = 2 * 60 * 60  # 2 hours

    def __init__(self, users_file: str, passwords_file: str):
        self.users_file = users_file
        self.passwords_file = passwords_file

        self.users = self._load_users()
        self.passwords = self._load_passwords()
        self.start_time = time.time()
        self.total_attempts = 0
        self.time_to_first_success = None    # Time till first crack
        self.num_users = len(self.users)  # total user count
        self.num_cracked = 0              # cracked users
        self.global_latency = 0.0 # for avg latency calculate
        self.summary = {
            "users": {},
            "by_category": defaultdict(list),
            "cpu": [],
            "mem": [],
            "start_time": self.start_time
        }

    # ---------- Loaders ----------

    def _load_users(self) -> List[str]:
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
            'http://localhost:5000/admin/get_captcha_token',
            params={"group_seed": self.GROUP_SEED, "username": username},
            timeout=5
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
    
    @staticmethod
    def attack_user_multi_process(args):
        simulator, username, threads_per_user = args
        simulator.attack_user_multithreaded(username, threads_per_user)
    
    def attack_user_multithreaded(self, username: str, num_threads: int = 5):
        category = self.get_category(username)

        user_stats = {
            "username": username,
            "password_found": None,
            "attempts": 0,
            "cracked": False,
            "time_to_success": None,
            # "latencies": [],
            "latency_sum":0.0,
            "last_latency": None,
            "totp_stopped": False
        }

        stop_event = threading.Event()
        stats_lock = threading.Lock()
        user_start = time.time()

        def worker(password: str):
            if stop_event.is_set():
                return

            payload = {"username": username, "password": password}
            resp, latency, status = self.attempt_login(payload)

            with stats_lock:
                self._record_attempt(user_stats, latency)

            # CAPTCHA
            if resp.get("captcha_required") and not stop_event.is_set():
                payload["captcha_token"] = self.handle_captcha(username)
                resp, latency, status = self.attempt_login(payload)
                with stats_lock:
                    self._record_attempt(user_stats, latency)

            # Permanent lock
            if status == 423 or "permanently locked" in resp.get("message", "").lower():
                print(f"[!] User {username} permanently locked")
                stop_event.set()
                return

            # TOTP
            if self.is_totp_required(resp):
                with stats_lock:
                    self._mark_success(user_stats, password, user_start, totp=True)
                print(f"[!] User {username} blocked by TOTP")
                stop_event.set()
                return

            # Success
            if resp.get("success"):
                with stats_lock:
                    self._mark_success(user_stats, password, user_start)
                    if self.time_to_first_success is None:
                        self.time_to_first_success = time.time() - self.start_time
                    self.num_cracked += 1
                print(f"[+] User {username} cracked! Password: {password}")
                stop_event.set()
                return

            if user_stats["attempts"] >= self.MAX_ATTEMPTS_PER_USER:
                stop_event.set()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for password in self.passwords:
                if stop_event.is_set() or self._should_stop():
                    break
                futures.append(executor.submit(worker, password))

            for _ in as_completed(futures):
                if stop_event.is_set():
                    break

        self.summary["users"][username] = user_stats
        self.summary["by_category"][category].append(user_stats)

        return user_stats

    # ---------- State Management ----------

    def _record_attempt(self, user_stats, latency):
        self.total_attempts += 1
        user_stats["attempts"] += 1
        user_stats["latency_sum"] += latency
        user_stats["last_latency"] = latency
        self.summary["cpu"].append(psutil.cpu_percent())
        self.summary["mem"].append(psutil.virtual_memory().percent)
        self.global_latency += latency

    def _mark_success(self, user_stats, password, start, totp=False):
        user_stats["cracked"] = True
        user_stats["password_found"] = password
        user_stats["time_to_success"] = time.time() - start
        user_stats["totp_stopped"] = totp
        
        if not totp:
            self.num_cracked += 1
            if self.time_to_first_success is None:
                self.time_to_first_success = user_stats["time_to_success"]

        with open("results.txt", "a") as f:
            f.write(f"{user_stats}\n")

    def _should_stop(self) -> bool:
        return (
            time.time() - self.start_time > self.MAX_RUNTIME or
            self.total_attempts >= self.MAX_TOTAL_ATTEMPTS
        )

    # ---------- Execution ----------

    def run(self, threads_per_user: int = 5, users_processes = 5):
        users = self.users
        print(f"\n [RUN {users_processes} USERS IN PARALLEL - multiprocessing  {threads_per_user} per user!] \n")

        futures = []
        results = []
        with ProcessPoolExecutor(max_workers=users_processes) as executor:
            for user in users:
                sim_clone = deepcopy(self)
                args = (sim_clone, user, threads_per_user)
                futures.append(executor.submit(BruteForceSimulator.attack_user_multi_process, args))
            # waiting for all processes to end
            for fut in as_completed(futures):
                user_stats = fut.result()
                if user_stats:  
                    results.append(user_stats)

        self.total_attempts = sum(u["attempts"] for u in results)
        self.num_cracked = sum(1 for u in results if u["cracked"] and not u["totp_stopped"])
        self.time_to_first_success = min([u["time_to_success"] for u in results if u["cracked"] and u["time_to_success"]], default=None)
        self.global_latency = sum(u["latency_sum"] for u in results)
        for u in results:
            cat = self.get_category(u["username"])
            self.summary["by_category"][cat].append(u)
        
        
        self.print_summary()

    
    # ---------- Reporting ----------

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
        
        success_rate = self.num_cracked / self.num_users * 100 if self.num_users else 0
        if self.time_to_first_success is not None:
            print(f"\nTime to first success: {self.time_to_first_success:.2f} seconds")
        else:
            print("\nTime to first success: No user cracked.")
        print(f"Success rate: {success_rate:.2f}%")

        if self.global_latency:
            avg_latency = (self.global_latency) / (self.total_attempts)
            print(f"Avg latency (ms): {avg_latency:.2f}")

        print(f"Avg CPU: {sum(self.summary['cpu'])/len(self.summary['cpu']):.1f}%" if self.summary["cpu"] else "")
        print(f"Avg RAM: {sum(self.summary['mem'])/len(self.summary['mem']):.1f}%" if self.summary["mem"] else "")

if __name__ == "__main__":
    user_path = os.path.join(os.path.dirname(__file__), "../src/users.json")
    passwords_path = os.path.join(os.path.dirname(__file__), "../test_passwords.txt")

    sim = BruteForceSimulator(
        users_file=user_path,
        passwords_file=passwords_path
    )
    # users_processes = each process will run on a different user
    # threads_per_user = each user will have threads
    sim.run(threads_per_user = 5,users_processes = 5) 
