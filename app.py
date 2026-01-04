import subprocess
from time import sleep
import os
import signal

server: subprocess.Popen = None

def signal_handler(sig, frame):
    print("\nTerminating...")
    server.terminate()
    server.wait()
    exit(0)
    

if __name__ == "__main__":
    # Get the VENV Python executable
    signal.signal(signal.SIGINT, signal_handler)
    
    venv_python = os.path.join(os.path.dirname(__file__), "VENV", "Scripts", "python.exe")
    
    print("=== Starting Server ===")
    server = subprocess.Popen([venv_python, "src/server.py"])
    sleep(3)  # Give the server time to start
    
    print("\n=== Generating Test Dataset (30 users: 10 weak + 10 medium + 10 strong) ===")
    subprocess.run([venv_python, "-m", "automation.test_users_generator", 
                   "--type", "weak",
                   "--count", "10",
                   "--host", "http://localhost:5000",
                   "--enable-totp",
                   "--output", "test_credentials.json"])
    subprocess.run([venv_python, "-m", "automation.test_users_generator", 
                   "--type", "medium",
                   "--count", "10",
                   "--host", "http://localhost:5000",
                   "--enable-totp",
                   "--output", "test_credentials.json"])
    subprocess.run([venv_python, "-m", "automation.test_users_generator", 
                   "--type", "strong",
                   "--count", "10",
                   "--host", "http://localhost:5000",
                   "--enable-totp",
                   "--output", "test_credentials.json"])
    print("\n✓ Done!")

