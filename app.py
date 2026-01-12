import subprocess
from time import sleep
import os
import signal
import argparse
import sys

server: subprocess.Popen = None


def signal_handler(sig, frame):
    print("\nTerminating...")
    if server:
        server.terminate()
        server.wait()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument("--gen", action="store_true", help="Generate test users")
    parser.add_argument("--BF_attack", action="store_true", help="Run brute force simulator")
    parser.add_argument("--PS_attack", action="store_true", help="Run password spray simulator")
    args = parser.parse_args()

    venv_python = os.path.join(
        os.path.dirname(__file__),
        "VENV",
        "Scripts",
        "python.exe"
    )

    print("=== Starting Server ===")
    server = subprocess.Popen([venv_python, "src/server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sleep(3)

    if args.gen:
        print("\n=== Generating Test Dataset ===")

        subprocess.run([
            venv_python, "-m", "automation.test_users_generator",
            "--type", "weak",
            "--count", "10",
            "--host", "http://localhost:5000",
            "--output", "test_credentials.json"
        ])

        subprocess.run([
            venv_python, "-m", "automation.test_users_generator",
            "--type", "medium",
            "--count", "10",
            "--host", "http://localhost:5000",
            "--output", "test_credentials.json"
        ])

        subprocess.run([
            venv_python, "-m", "automation.test_users_generator",
            "--type", "strong",
            "--count", "10",
            "--host", "http://localhost:5000",
            "--enable-totp",
            "--output", "test_credentials.json"
        ])

    if args.BF_attack:
        print("\n=== Running Brute Force Simulator ===")
        subprocess.run([
            venv_python, "-m", "automation.brute_force_simulator",
            "--host", "http://localhost:5000",
            "--input", "test_credentials.json"
        ])
    if args.PS_attack:
        print("\n=== Running password spray Simulator ===")
        subprocess.run([
            venv_python, "-m", "automation.password_spraying_simulator",
            "--host", "http://localhost:5000",
            "--input", "test_credentials.json"
        ])

    print("\nDone!")
