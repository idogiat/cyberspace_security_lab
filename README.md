# cyberspace_security_lab
A project that investigates protection mechanisms for password authentication


## Researches:
- [PEPPER](https://github.com/idogiat/cyberspace_security_lab/blob/feature/flask_server/docs/PEPPER.md)
- [Password Spraying Attack](https://github.com/idogiat/cyberspace_security_lab/blob/feature/flask_server/docs/Password%20Spraying%20Attack.md)
- [TOTP](https://github.com/idogiat/cyberspace_security_lab/blob/feature/TOTP_research/docs/TOTP.md)



## Setup
- Install python 3.13.2 (at least 3.10)
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