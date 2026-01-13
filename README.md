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
        ```
            [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
        ```
        in Python: 
    ```
            import secrets
            import base64

            pepper = base64.b64encode(secrets.token_bytes(32)).decode()
            print(pepper)
        ```
- configure the config.json file prior to running the server:
```
  "AUTOMATION_GEN_USERS_HASH_MODE":0,  # 0 = 'Argon2' / 1 = 'bcrypt' / 2 = 'SHA-256 + SALT' 
  "AUTOMATION_GEN_USERS_TOTP":false,   # strong level automated users [true/false]
  "LOCKOUT_ACTIVATED":false,           # user lockout [true/false]
  "LOCKOUT_THRESHOLD": 20,             # login attempts until lockout is activated [int]
  "RATE_LIMIT_ACTIVATED":false,        # Rate Limit lockout [true/false]
  "RATE_LIMIT_ATTEMPTS": 10,           # login attempts until Rate-Limit is activated [int]
  "RATE_LIMIT_LOCK_SEC": 60,           # Rate Limit lockout time in seconds [int]
  "CAPTCHA_ACTIVATED":true,            # Captcha lockout [true/false]
  "CAPTCHA_THRESHOLD":20               # login attempts until Captcha is activated [int]
```

* "AUTOMATION_GEN_USERS_HASH_MODE" is used for Generate test users automation (`python ./app.py --gen`)

- Run the following commands:
```
python -m venv VENV
source .\VENV\Scripts\activate
pip install -r .\requirements.txt
```

## Run full simulator
in order to run automaticly full simulator with multiple configurations, run the following command:
`python full_simulation.py`
it will take a lot of time
- generate users per configuration
- run brute force
- run password spraing
At the end `results` folder will be created.
- The simulator run different configurations from test_confs.json


# Manual running:
choose your flag and run it accordingly
This will start the server and generate a test dataset with 30 users.

Or run server manually:
```
python ./src/server.py
connect to http://127.0.0.1:5000/
```

## Test Dataset

The `app.py` script automatically generates 30 test users (10 weak, 10 medium, 10 strong)
run: `python app.py --gen` to generate users in db
run: `python app.py --attack-brute-force` to run attack brute force simulator 
run: `python app.py --attack-password-spraying` to run attack password spraing simulator

### Features:
- All users have TOTP (Time-based One-Time Password) enabled for 2FA testing
- Credentials saved to `test_credentials.json`
- Suitable for testing password spraying, brute force, and TOTP authentication mechanisms