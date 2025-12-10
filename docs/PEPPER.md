# Research: PEPPER in Online Security

## Background

**Peppering** is a cryptographic technique designed to strengthen password storage. In the context of online security, a pepper is a secret value, separate from user-specific salts, 
that is combined with a password before hashing. 
Unlike salts, which are unique and stored for each user, a pepper is kept confidential often at the application or server level and is not stored alongside the 
password hashes in the database.provide an additional layer of protection. 
It prevents an attacker from being able to crack any of the hashes if they only have access to the database, for example, if they have exploited a SQL injection vulnerability or obtained a backup of the database.

## Common Uses

- Enhancing password storage security above and beyond salting and hashing.
- Securing environments where stored salted hashes may be exposed.
- Providing defense-in-depth for sensitive authentication systems and high-value assets.

### Components
- Password (user input)
- Salt (unique per user, stored in DB)
- Pepper (secret, not stored in DB)
- Hashing algorithm (e.g., bcrypt, Argon2, PBKDF2)

### General Process
1. Password + Pepper → Concatenate (or combine securely)
2. Result + Salt → Hash using strong algorithm
3. Store only the hash and salt; keep the pepper secret

#### Requirements
- Secure and secret storage of the pepper (e.g., Hardware Security Module, environment variables)
- Never store the pepper in the database alongside password hashes

## Advantages and Disadvantages

### Advantages
- Extra layer of security if database is breached
- Makes offline brute-force attacks significantly harder

### Disadvantages
- If the pepper is leaked, attackers gain a significant advantage
- Pepper management adds complexity (rotation, storage, distribution)
- Unsuitable for systems that need to hash/check passwords client-side

## Limitations

- Protects only against attackers without access to the pepper; if application/server is compromised, attacks become feasible
- Ineffective if pepper is weak, reused, or exposed within source code

## Types of Pepper

1. **Static Pepper**:  
   The same pepper value is used across the entire system. Kept secret, often in secure storage. **(most common)**
2. **User-specific Pepper**:  
   Each user is assigned a unique pepper. Much harder to implement and manage securely.
3. **Secret Key Derivation Pepper**:  
   Pepper is derived from a secret key or secure computation at runtime.

## How Pepper Works (core components and requirements for Peppering strategies)


## Pre-hashing peppers most common ##

In this strategy, a pepper is added to a password *before* being hashed by a password hashing algorithm. The computed hash is then stored in the database. In this case the pepper should be a random value generated securely.
e.g. `hash(password + salt + pepper)`

## Post-hashing peppers ##

In this strategy, a password is hashed as usual using a password hashing algorithm. The resulting password hash is then hashed again using an HMAC (e.g., HMAC-SHA256, HMAC-SHA512, depending on the desired output length) before storing the resulting hash in the database. In this case the pepper is acting as the HMAC key and should be generated as per requirements of the HMAC algorithm.
e.g., `hash(hash(password + salt) + pepper)`. 
This method is sometimes used to retrofit systems with peppering capabilities without re-hashing all existing user passwords, but it’s more complex and less common.

## Attacks and Protections With Pepper

### Typical Attacks
- **Database breach**: Attackers can’t crack passwords without the pepper
- **Insider attack**: Pepper leakage can compromise the system

### Protections
- Store pepper outside the database, in a secure key store or environment variable
- Rotate pepper if exposure is suspected, Peppers cannot be changed without knowledge of a user's password. 
  Therefore changing a pepper will require forcing all users whose passwords were protected by the previous pepper to reset their passwords.
- Use together with strong, relatively slow hashing algorithms (bcrypt, Argon2)

Pepper is most effective when attackers obtain the database with the hashed passwords (offline attack scenario). It is not a defense against online brute-force or password spraying, because the validation routine on the server uses the pepper internally.
Instead, it adds a crucial layer of security by making offline brute-force attacks much harder. If an attacker does not know the secret pepper, any attempt to brute-force password hashes from a leaked database will fail, even if they have access to the salts and the hash algorithm.

Summary:

With Pepper: Attackers must guess the password and the secret pepper for each guess–dramatically increasing the difficulty and time required.
Without Pepper: Attackers only need to brute-force the password (with salt), which is much easier if they have weak passwords and/or fast hash functions.
For online attacks, pepper offers no additional protection, so account lockout, rate limiting, and MFA are required.

## Implementing PEPPER in Python

# Install the bcrypt library
```bash
pip install bcrypt
```
# Generate a Secret Pepper
It is wise to use a randomly generated string, ideally loaded from an environment variable or a secure location:
```python
import os
pepper = os.urandom(16).hex()  # Example random pepper (could also use a strong fixed secret)
```
# Hash a Password with Salt and Pepper
```python

import bcrypt
import os

pepper = os.environ.get('PEPPER_SECRET', 'defaultpepper')  # Store your real pepper securely!

def hash_password(password, pepper):
    password_peppered = (password + pepper).encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_peppered, salt)
    return hashed, salt

# Usage
hashed_pw, salt = hash_password('userPassword!', pepper)
print(hashed_pw)
```

# Verify a password
```python

def verify_password(password_attempt, hashed, pepper):
    password_peppered = (password_attempt + pepper).encode('utf-8')
    return bcrypt.checkpw(password_peppered, hashed)
```

## Example of a PEPPER Attack (Educational Purpose)

simple (inefficient) brute-force scenario:

```python
import bcrypt

# Simulated stolen hash and salt (assume attacker got these from DB)
hashed = b"$2b$12$p6op8YamRmCBgVbgxuy7wOEuA2N7uIzAbm9PguImtOElDFHBa8BcC"
salt = b"$2b$12$p6op8YamRmCBgVbgxuy7wO"

# The attacker also suspects the password is 'admin', but doesn't know the pepper
possible_peppers = ['pepper1', 'pepper2', 'mysecret', 'superpepper']

for pepper in possible_peppers:
    test = ('admin' + pepper).encode('utf-8')
    if bcrypt.checkpw(test, hashed):
        print(f"Found matching pepper: {pepper}")
        break
else:
    print("No pepper from the list worked.")

```


## Resources and Useful Links

- [OWASP Password Storage Cheat Sheet: Peppering](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#peppering)  
  Best practices and technical overview of pepper in password security.

- [RFC 4793: A Method for Key Derivation Using Cryptographic Hash Functions](https://datatracker.ietf.org/doc/html/rfc4793)  
  Standard for secret key derivation which can relate to peppering strategies.

- [Added Security with Salt and Pepper – A Recipe for Securer Storage (Compliiant Blog)](https://blog.compliiant.io/added-security-with-salt-and-pepper-a-recipe-for-securer-storage-4a884a060b9b)  
  Explainer and practical considerations in salting and peppering passwords.

- [bcrypt Python library documentation](https://pypi.org/project/bcrypt/)  
  Library used for hashing and securely storing passwords.


---


## Summary 

This document serves as a practical reference for implementing pepper securely, integrating it with modern cryptology tools, recognizing its operational boundaries, 
and combining it with additional security measures to maximize user and system protection.
