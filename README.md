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
python ./src/server.py
connect to http://127.0.0.1:5000/
```