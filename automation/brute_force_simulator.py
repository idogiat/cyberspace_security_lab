import os
import sys
import time
import json
import signal
import psutil
import requests
import threading
from typing import List
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from copy import deepcopy
<<<<<<< HEAD
=======

shutdown_event = threading.Event()
print_lock = threading.Lock()   # ✅ חדש – למניעת ערבוב prints

# ---------- CTRL+C ----------
def handle_ctrl_c(signum, frame):
    print("\n[!] Ctrl+C received — shutting down gracefully...")
    shutdown_event.set()

signal.signal(signal.SIGINT, handle_ctrl_c)

# ---------- HELPERS ----------
def chunkify(lst, n):
    """Split list lst into n roughly equal chunks (SAFE)"""
    if n <= 0:
        return [lst]
    n = min(n, len(lst))
    size = (len(lst) + n - 1) // n
    return [lst[i:i + size] for i in range(0, len(lst), size)]
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7

shutdown_event = threading.Event()

def handle_ctrl_c(signum, frame):
    print("\n[!] Ctrl+C received — shutting down gracefully...")
    shutdown_event.set()

signal.signal(signal.SIGINT, handle_ctrl_c)


def chunkify(lst, n):
    """Split list lst into n roughly equal chunks
    If the list doesn't divide evenly, some chunks will have one more element.
    For example, chunkify(list(range(10)), 3) =>
    [
        [0,1,2,3],
        [4,5,6],
        [7,8,9]
    ]
    """

    k, m = divmod(len(lst), n)  # k is the minimal chunk size, m is the number of larger chunks (gets +1 item in case of uneven split)
    chunks = []
    for i in range(n):
        # measuring the sub list to make sure there won't be overlaping password between chunks
        start = i * k + min(i, m)
        end = (i + 1) * k + min(i + 1, m)
        chunks.append(lst[start:end])
    return chunks

# =========================
# BRUTE FORCE SIMULATOR
# =========================
class BruteForceSimulator:
    SERVER_URL = 'http://localhost:5000/api/login'
    GROUP_SEED = 524392612
    MAX_ATTEMPTS_PER_USER = 50_000
    MAX_TOTAL_ATTEMPTS = 1_000_000
    MAX_RUNTIME = 2 * 60 * 60  # 2 hours

    def __init__(self, users_file: str, weak_file: str, medium_file: str, strong_file: str):
        self.users_file = users_file
        self.weak_file = weak_file
        self.medium_file = medium_file
        self.strong_file = strong_file

        self.users = self._load_users()
        self.passwords_by_category = self._load_passwords()
        self.start_time = time.time()
        self.total_attempts = 0
<<<<<<< HEAD
        self.time_to_first_success = None    # Time till first crack
        self.num_users = len(self.users)  # total user count
        self.num_cracked = 0              # cracked users
        self.global_latency = 0.0 # for avg latency calculate
=======
        self.time_to_first_success = None
        self.num_users = len(self.users)
        self.num_cracked = 0
        self.global_latency = 0.0
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7
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

    def _load_passwords(self) -> dict:
        def load_file(path):
            if not os.path.exists(path):
                return []
            with open(path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]

        return {
            "weak": load_file(self.weak_file),
            "medium": load_file(self.medium_file),
            "strong": load_file(self.strong_file)
        }

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
    
    def attack_user_multithreaded(self, username: str, num_threads: int = 5):
        category = self.get_category(username)
        passwords = self.passwords_by_category.get(category, [])

        user_stats = {
            "username": username,
            "password_found": None,
            "attempts": 0,
            "cracked": False,
            "time_to_success": None,
<<<<<<< HEAD
            "latency_sum":0.0,
            "last_latency": None,
            "totp_stopped": False,
            "absolute_first_success": None,
            "cpu_sum": 0.0,
            "cpu_count": 0,
            "mem_sum": 0.0,
            "mem_count": 0,
=======
            "latency_sum": 0.0,
            "last_latency": None,
            "totp_stopped": False
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7
        }

        stop_event = threading.Event()
        stats_lock = threading.Lock()
        user_start = time.time()

        def worker(password: str):
            if stop_event.is_set() or shutdown_event.is_set():
                return

            if self._should_stop():
                stop_event.set()
                return

            with print_lock:
                print(f"[TRY] {username}:{password}")

            payload = {"username": username, "password": password}
            print(f"Trying {username}:{password}")
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
                stop_event.set()
                return

            # TOTP
            if self.is_totp_required(resp):
                with stats_lock:
                    self._mark_success(user_stats, password, user_start, totp=True)
                stop_event.set()
                return

            # Success
            if resp.get("success"):
                with stats_lock:
                    self._mark_success(user_stats, password, user_start)
<<<<<<< HEAD
                    if "absolute_first_success" not in user_stats or not user_stats["absolute_first_success"]:
                        user_stats["absolute_first_success"] = time.time()
                    # self.num_cracked += 1
                print(f"[+] User {username} cracked! Password: {password}")
=======
                    if self.time_to_first_success is None:
                        self.time_to_first_success = time.time() - self.start_time
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7
                stop_event.set()
                return

            if user_stats["attempts"] >= self.MAX_ATTEMPTS_PER_USER:
                stop_event.set()

        def thread_worker(passwords_chunk: List[str]):
<<<<<<< HEAD
            # print(f"Thread {threading.current_thread().name} got chunk (len={len(passwords_chunk)}): {passwords_chunk[:5]} ... {passwords_chunk[-5:]}")
            for password in passwords_chunk:
                if stop_event.is_set():
                    break
                worker(password)
    
        password_chunks = chunkify(self.passwords, num_threads)
        # for i, chunk in enumerate(password_chunks):
            # print(f"Chunk {i}: first 5={chunk[:5]}, last 5={chunk[-5:]}, length={len(chunk)}")
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(thread_worker, chunk) for chunk in password_chunks]

            for fut in as_completed(futures):
                if stop_event.is_set():
=======
            for password in passwords_chunk:
                if stop_event.is_set() or shutdown_event.is_set():
                    break
                worker(password)

        password_chunks = chunkify(passwords, num_threads)
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(thread_worker, chunk) for chunk in password_chunks]
            for _ in as_completed(futures):
                if stop_event.is_set() or shutdown_event.is_set():
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7
                    break

        self.summary["users"][username] = user_stats
        self.summary["by_category"][category].append(user_stats)

        return user_stats
<<<<<<< HEAD

    # ---------- State Management ----------
=======
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7

    # ---------- State Management ----------
    def _record_attempt(self, user_stats, latency):
        self.total_attempts += 1
        user_stats["attempts"] += 1
        user_stats["latency_sum"] += latency
        user_stats["last_latency"] = latency
<<<<<<< HEAD
        # self.summary["cpu"].append(psutil.cpu_percent())
        # self.summary["mem"].append(psutil.virtual_memory().percent)
        cpu_now = psutil.cpu_percent()
        mem_now = psutil.virtual_memory().percent
        user_stats["cpu_sum"] += cpu_now
        user_stats["cpu_count"] += 1
        user_stats["mem_sum"] += mem_now
        user_stats["mem_count"] += 1
        self.global_latency += latency


=======
        self.summary["cpu"].append(psutil.cpu_percent())
        self.summary["mem"].append(psutil.virtual_memory().percent)
        self.global_latency += latency
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7

    def _mark_success(self, user_stats, password, start, totp=False):
        user_stats["cracked"] = True
        user_stats["password_found"] = password
        user_stats["time_to_success"] = time.time() - start
        user_stats["absolute_first_success"] = time.time()
        user_stats["totp_stopped"] = totp

<<<<<<< HEAD
        if not totp:
            self.num_cracked += 1 # saved as cracked only if it's not defended by totp
            if self.time_to_first_success is None:
                self.time_to_first_success = user_stats["time_to_success"]

=======
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7
        with open("results.txt", "a") as f:
            f.write(f"{user_stats}\n")

    def _should_stop(self) -> bool:
        return (
            time.time() - self.start_time > self.MAX_RUNTIME or
            self.total_attempts >= self.MAX_TOTAL_ATTEMPTS
        )

    # ---------- Execution ----------
    def run(self, threads_per_user: int = 5, users_processes=5):
        users = self.users
        print(f"\n [RUN {users_processes} USERS IN PARALLEL - multiprocessing  {threads_per_user} per user!] \n")

<<<<<<< HEAD
    def run(self, threads_per_user: int = 5, users_processes = 5):
        users = self.users
        print(f"\n [RUN {users_processes} USERS IN PARALLEL - multiprocessing  {threads_per_user} per user!] \n")
=======
        with ProcessPoolExecutor(max_workers=users_processes) as executor:
            results = list(executor.map(self.attack_user_multithreaded, users,[threads_per_user]*len(users)))

        self.total_attempts = sum(u["attempts"] for u in results)
        self.num_cracked = sum(1 for u in results if u["cracked"] and not u["totp_stopped"])
        self.time_to_first_success = min(
            [u["time_to_success"] for u in results if u["cracked"] and u["time_to_success"]],
            default=None
        )
        self.global_latency = sum(u["latency_sum"] for u in results)

        for u in results:
            cat = self.get_category(u["username"])
            self.summary["by_category"][cat].append(u)
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7

        with ProcessPoolExecutor(max_workers=users_processes) as executor:
            results = list(executor.map(self.attack_user_multithreaded, users, [threads_per_user]*len(users)))

        self.total_attempts = sum(u["attempts"] for u in results)
        self.num_cracked = sum(1 for u in results if u["cracked"] and not u["totp_stopped"])
        self.time_to_first_success = min([u["time_to_success"] for u in results if u["cracked"] and u["time_to_success"]], default=None)
        self.global_latency = sum(u["latency_sum"] for u in results)

        absolute_success_times = [u["absolute_first_success"]
        for u in results if u["cracked"] and not u["totp_stopped"] and u.get("absolute_first_success")
    ]

        if absolute_success_times:
            self.time_to_first_success = min(absolute_success_times) - self.start_time
        else:
            self.time_to_first_success = None
        
        cpu_vals = []
        mem_vals = []
        for u in results:
            cat = self.get_category(u["username"])
            self.summary["by_category"][cat].append(u)
        if u["cpu_count"]:
            cpu_vals.append(u["cpu_sum"] / u["cpu_count"])
        if u["mem_count"]:
            mem_vals.append(u["mem_sum"] / u["mem_count"])
    
        self.avg_cpu = sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0
        self.avg_mem = sum(mem_vals) / len(mem_vals) if mem_vals else 0
            
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
        print(f"Avg cpu: {self.avg_cpu}%")
        print(f"Avg RAM: {self.avg_mem}%")

        success_rate = self.num_cracked / self.num_users * 100 if self.num_users else 0
        if self.time_to_first_success is not None:
            print(f"\nTime to first success: {self.time_to_first_success:.2f} seconds")
        else:
            print("\nTime to first success: No user cracked.")
        print(f"Success rate: {success_rate:.2f}%")

        if self.global_latency:
            avg_latency = self.global_latency / self.total_attempts
            print(f"Avg latency (ms): {avg_latency:.2f}")

        if self.summary["cpu"]:
            print(f"Avg CPU: {sum(self.summary['cpu'])/len(self.summary['cpu']):.1f}%")
        if self.summary["mem"]:
            print(f"Avg RAM: {sum(self.summary['mem'])/len(self.summary['mem']):.1f}%")


if __name__ == "__main__":
    base_dir = os.path.dirname(__file__)
    user_path = os.path.join(base_dir, "../src/users.json")
    weak_path = os.path.join(base_dir, "passwords_weak.txt")
    medium_path = os.path.join(base_dir, "passwords_medium.txt")
    strong_path = os.path.join(base_dir, "passwords_strong.txt")

    sim = BruteForceSimulator(
        users_file=user_path,
        weak_file=weak_path,
        medium_file=medium_path,
        strong_file=strong_path
    )
<<<<<<< HEAD
    # users_processes = each process will run on a different user
    # threads_per_user = each user will have threads
    sim.run(threads_per_user = 10, users_processes = 10) 
=======

    sim.run(threads_per_user=10, users_processes=10)
>>>>>>> 15a9316c78cb92136c60c807f27868f260c46cb7
