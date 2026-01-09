# cyberspace_security_lab
A project that investigates protection mechanisms for password authentication


## Researches:
- [PEPPER](https://github.com/idogiat/cyberspace_security_lab/blob/feature/flask_server/docs/PEPPER.md)
- [Password Spraying Attack](https://github.com/idogiat/cyberspace_security_lab/blob/feature/flask_server/docs/Password%20Spraying%20Attack.md)
- [TOTP](https://github.com/idogiat/cyberspace_security_lab/blob/feature/TOTP_research/docs/TOTP.md)



## Setup


- Install python 3.13.2 (at least 3.10)
- For using PEPPER (Do these steps before running the server): 
    please add an environment variable name: PASSWORD_PEPPER
    add the value of your PEPPER secret to the PASSWORD_PEPPER environment variable.
        - to generate a pepper secret: 
        in Powershell: 
            [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
        in Python: 
                ```
                import secrets
                import base64

                pepper = base64.b64encode(secrets.token_bytes(32)).decode()
                print(pepper)
                ```


- Run the following commands:
```
python -m venv VENV
source .\VENV\Scripts\activate
pip install -r .\requirements.txt
```


## run:
```
python app.py --help
```
output:
```

$ python ./app.py --help
usage: app.py [-h] [--gen] [--attack]

options:
  -h, --help  show this help message and exit
  --gen       Generate test users
  --attack    Run brute force simulator
```

choose your flag and run it accordingly

This will start the server and generate a test dataset with 30 users.

Or run server manually:
```
python ./src/server.py
connect to http://127.0.0.1:5000/
```

## Test Dataset

The `app.py` script automatically generates 30 test users for security research:

### Weak Passwords (10 users) - for brute force attack testing
- Username pattern: `loaduser_weak_0` to `loaduser_weak_9`
- Passwords: `123456`, `password`, `12345678`, `qwerty`, `abc123`, etc.
- Purpose: Simulate vulnerable accounts that are easily compromised via brute force attacks

### Medium Passwords (10 users) - for standard security testing
- Username pattern: `loaduser_medium_0` to `loaduser_medium_9`
- Passwords: `Test1234`, `Secure99`, `KeyPass1`, `Demo2024`, `Admin@123`, etc.
- Purpose: Baseline accounts with moderate password complexity

### Strong Passwords (10 users) - for advanced attack testing
- Username pattern: `loaduser_strong_0` to `loaduser_strong_9`
- Passwords: `Str0ng!P@ssw0rd#2024`, `C0mpl3x&S3cur3T0ken!`, etc.
- Purpose: Simulate well-protected accounts resistant to brute force attacks

### Features:
- All users have TOTP (Time-based One-Time Password) enabled for 2FA testing
- Credentials saved to `test_credentials.json`
- Suitable for testing password spraying, brute force, and TOTP authentication mechanisms