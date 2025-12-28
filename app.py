
import subprocess
from time import sleep
import os

if __name__ == "__main__":
    # Get the VENV Python executable
    venv_python = os.path.join(os.path.dirname(__file__), "VENV", "Scripts", "python.exe")
    
    print("=== Starting Server ===")
    server = subprocess.Popen([venv_python, "src/server.py"])
    sleep(3)  # Give the server time to start
    
    print("\n=== Generating Test Users ===")
    subprocess.run([venv_python, "automation/test_users_generator.py", "--count", "50", "--enable-totp", "--output", "src/users.json"])
    print("\n Done!")

