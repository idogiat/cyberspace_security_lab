# Password Spraying Attack

## Background

**Password spraying** is a type of brute-force attack targeting large numbers of usernames with a small set of commonly used passwords. Unlike traditional brute-force methods, which test many passwords for a single user, password spraying tries one or a few common passwords across many accounts, minimizing the chance of account lockout due to failed login attempts. This method is widely used by attackers to compromise enterprise systems because users often select weak or commonly used passwords.
For example, an attacker will use one password (say, Secure@123) against many different accounts on the application to avoid account lockouts that would normally occur when brute forcing a single account with many passwords.

This attack can be found commonly where the application or admin sets a default password for the new users.

## Common Uses

- **Compromising enterprise networks**: Attacking corporate accounts using default or weak passwords.
- **Initial access**: Used as a first step in breaching organizations before privilege escalation or lateral movement.
- **Bypassing account lockout policies**: Avoiding detection and automatic account locks by limiting the number of attempts per user.

## How It Works + Process

### The Attack Process

1. **Gathering Usernames**: The attacker collects a list of valid usernames (e.g., via LinkedIn, corporate directories, or email patterns).
2. **Selecting Common Passwords**: A list of weak or commonly used passwords is prepared (e.g., "Password1", "123456", "Winter2024").
3. **Attempting Logins**: The attacker attempts to log in to each account with each password, limiting the number of tries per account to avoid lockout.
4. **Identifying Success**: When valid credentials are found, attackers gain access and can escalate privileges or pivot within the target environment.

## Defending Against Password Spraying

- **Enforce strong password policies**: Require complex passwords that are not easily guessable.
- **Implement account lockout or throttling**: Temporarily lock or delay accounts after a few failed attempts.
- **Multi-factor authentication (MFA)**: Adds another layer that password spraying can't easily bypass.
- **Monitor and alert on suspicious activity**: Detect excessive failed login attempts across accounts.
- **Restrict remote access protocols**: Limit and harden RDP, VPN, and other externally accessible services.
- **Regularly audit accounts**: Remove unused or default accounts.

## Implementation in Python (For Educational Purposes Only)

**Disclaimer:** The following code and techniques are for educational and awareness purposes; do not use for unauthorized testing.

### Simulating a Password Spraying Attack


```python
import requests
# requests - For sending HTTP login attempts.

usernames = ["alice", "bob", "charlie"]
passwords = ["Password1", "Welcome2024"]

login_url = "https://example.com/login"

for password in passwords:
    for username in usernames:
        response = requests.post(login_url, data={"username": username, "password": password})
        if "successful login" in response.text:
            print(f"Login succeeded: {username}:{password}")
        else:
            print(f"Failed login: {username}")

```

For real-world defense, use flask_limiter or similar to rate-limit attempts in your web apps.

## Example Python Projects

[brutespray](https://github.com/x90skysn3k/brutespray) - Automates spraying credentials across services.

[SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) - Set of password spraying attack tools (educational/research use).

[medusa](https://github.com/jmk-foofus/medusa) - Parallel login brute-forcer supporting many services.


## Resources and Useful Links

[OWASP: Password Spraying Attack]([https://](https://owasp.org/www-community/attacks/Password_Spraying_Attack))
Industry overview of the attack and defensive recommendations.

[MITRE ATT&CK: T1110.003 - Password Spraying]([https://](https://attack.mitre.org/techniques/T1110/003/))
Tactics, techniques, and examples in penetration simulations.

[brutespray](https://github.com/x90skysn3k/brutespray)
Open source automated spraying and brute-force tool.

## Summary
Password spraying is a real and evolving threat that targets weaknesses in password policy and authentication. By understanding how attackers automate and orchestrate these attacks, defenders can implement stronger password requirements, rate-limiting, account lockouts, and multi-factor authentication to significantly reduce risk. Prevention starts with user education and robust technical controls.
