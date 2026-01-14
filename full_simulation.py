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


def update_configuration(AUTOMATION_GEN_USERS_HASH_MODE: int =0,
                        AUTOMATION_GEN_USERS_TOTP: bool = False,
                        Automated_GEN_USERS_PEPPER: bool = False,
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
            "AUTOMATION_GEN_USERS_HASH_MODE": AUTOMATION_GEN_USERS_HASH_MODE,
            "AUTOMATION_GEN_USERS_TOTP": AUTOMATION_GEN_USERS_TOTP,
            "Automated_GEN_USERS_PEPPER":Automated_GEN_USERS_PEPPER,
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
    path = Path(__file__).parent
    print("=== Cleaning Environment ===")
    (path / "test_credentials.json").unlink(missing_ok=True)
    (path / "attempts.log").unlink(missing_ok=True)
    (path / "automation" / "passwords_weak.txt").unlink(missing_ok=True)
    (path / "automation" / "passwords_medium.txt").unlink(missing_ok=True)
    (path / "automation" / "passwords_strong.txt").unlink(missing_ok=True)
    (path / "automation" / "combined_passwords.txt").unlink(missing_ok=True)
    (path / "results.txt").unlink(missing_ok=True)
    (path / "users.db").unlink(missing_ok=True)


    config: dict = {}
    with open("src/users.json", "r") as f:
        config = json.load(f)
        config["users"] = []

    with open("src/users.json", "w") as f:
        json.dump(config, f, indent=4)

def save_results(name: str) -> None:

    base_path = Path(__file__).parent
    path = base_path / "results" / name
    os.makedirs(path, exist_ok=True)

    shutil.copy(base_path / "results.txt", path / "results.txt")
    shutil.copy(base_path / "attempts.log", path / "attempts.log")
    shutil.copy(base_path / "password_spray_summary.xlsx", path / "password_spray_summary.xlsx")
    shutil.copy(base_path / "brute_force_summary.xlsx", path / "brute_force_summary.xlsx")
    shutil.copy(base_path / "user.db", path / "user.db")


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
