import os
import sys
import json
import shutil
import signal
import subprocess
from pathlib import Path

TEST_CONFS_PATH = Path(__file__).parent / "test_confs.json"

venv_python = os.path.join(
        os.path.dirname(__file__),
        "VENV",
        "Scripts",
        "python.exe")

def signal_handler(sig, frame):
    print("\n[!] Terminating simulation...")
    server: subprocess.Popen | None = None
    if server and server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    sys.exit(0)


def update_configuration(USERS_HASH_MODE: int = 0,
                         USERS_TOTP: bool = False,
                         USERS_PEPPER: bool = False,
                         LOCKOUT_ACTIVATED: bool = False,
                         LOCKOUT_THRESHOLD: int = 45,
                         RATE_LIMIT_ACTIVATED: bool = False,
                         RATE_LIMIT_ATTEMPTS: int = 10,
                         RATE_LIMIT_LOCK_SEC: int = 60,
                         CAPTCHA_ACTIVATED: bool = False,
                         CAPTCHA_THRESHOLD: int = 20) -> None:
    
    config_path = Path(__file__).parent / "src" / "config.json"
    config: dict = {}
    with open(config_path, "r") as f:
        config = json.load(f)
        config.update({
            "USERS_HASH_MODE": USERS_HASH_MODE,
            "USERS_TOTP": USERS_TOTP,
            "USERS_PEPPER": USERS_PEPPER,
            "LOCKOUT_ACTIVATED": LOCKOUT_ACTIVATED,
            "LOCKOUT_THRESHOLD": LOCKOUT_THRESHOLD,
            "RATE_LIMIT_ACTIVATED": RATE_LIMIT_ACTIVATED,
            "RATE_LIMIT_ATTEMPTS": RATE_LIMIT_ATTEMPTS,
            "RATE_LIMIT_LOCK_SEC": RATE_LIMIT_LOCK_SEC,
            "CAPTCHA_ACTIVATED": CAPTCHA_ACTIVATED,
            "CAPTCHA_THRESHOLD": CAPTCHA_THRESHOLD
        })
    with open(config_path, "w") as f:
        json.dump(config, f, indent=4)

def clean_environment() -> None:
    base = Path(__file__).parent
    print("=== Cleaning Environment ===")

    files_to_remove = [
        base / "test_credentials.json",
        base / "attempts.log",
        base / "results.txt",
        base / "users.db",
        base / "password_spray_summary.csv",
        base / "brute_force_summary.csv",
        base / "automation" / "passwords_weak.txt",
        base / "automation" / "passwords_medium.txt",
        base / "automation" / "passwords_strong.txt",
        base / "automation" / "combined_passwords.txt",
    ]

    for f in files_to_remove:
        try:
            f.unlink()
        except FileNotFoundError:
            print(f"[!] File {f} not found, skipping.")
        except Exception as e:
            print(f"[!] Error removing file {f}: {e}")


    # Reset users.json cleanly
    users_path = base / "src" / "users.json"
    with open(users_path, "r") as f:
        data = json.load(f)

    data["users"] = []

    with open(users_path, "w") as f:
        json.dump(data, f, indent=4)


def save_results(name: str) -> None:
    base = Path(__file__).parent
    dst = base / "results" / name
    dst.mkdir(parents=True, exist_ok=True)

    files_to_save = [
        "results.txt",
        "attempts.log",
        "password_spray_summary.csv",
        "brute_force_summary.csv",
        "users.db",
    ]

    for filename in files_to_save:
        src = base / filename
        if src.exists():
            shutil.copy(src, dst / filename)
        else:
            print(f"[!] Missing {filename} — skipping")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    clean_environment()

    for conf_name, conf_values in json.load(open(TEST_CONFS_PATH, "r")).items():
        print(f"\n\n########## Running simulation for configuration: {conf_name} ##########\n")
        update_configuration(**conf_values)
        subprocess.run([venv_python, "-m", "app", "--gen"])
        subprocess.run([venv_python, "-m", "app", "--attack-brute-force"])
        subprocess.run([venv_python, "-m", "app", "--attack-password-spraying"])
        save_results(conf_name)
        clean_environment()
