# Research: TOTP – Time-based One-Time Password

## Background

TOTP is an algorithm for generating a time‑based one‑time password. It is part of an open standard by the IETF (RFC 6238) and is widely used in two‑factor authentication (2FA) systems such as Google Authenticator, Authy, and others.

The central idea: instead of using a fixed password, the user proves identity using a short code based on a shared secret key and the current time. The code usually changes every 30 seconds, making it difficult for an attacker to reuse it.

---

## Common Uses

* **Two‑Factor Authentication (2FA)**
* **Enterprise authentication** (VPN, SSH, dashboards)
* **Mobile apps** that need offline authentication
* **Financial and highly secure systems** (banks, crypto exchanges, trading platforms)

---

## How TOTP Works – Core Concepts

TOTP is based on HOTP, but instead of a counter it uses time.

### Components

1. **Shared Secret** – A Base32 string shared between server and client.
2. **Current Time** – Split into time windows (typically 30 seconds).
3. **HMAC-SHA1 / SHA256 / SHA512** – Hash function with the shared secret.
4. **Dynamic Truncation** – Extracting a numeric code from the HMAC.

### TOTP Generation Process

1. Calculate: `T = floor(current_time / 30)`
2. Compute HMAC with the secret key and T
3. Apply Dynamic Truncation to extract a number
4. Apply `mod 10^digits` to get a 6–8 digit code

---

## Advantages

* No communication required between server and client
* Codes change frequently → reduces replay attacks
* Open standard, widely supported
* Easy to implement

## Limitations

* Requires accurate time sync
* Not ideal for environments with high latency
* If the secret leaks → system is compromised

---

## Possible Attacks on TOTP

### 1. **Brute Force**

Low probability due to the short validity window.

### 2. **Desynchronization**

Time drift between server and client.

### 3. **Phishing / MITM**

User enters the code into a fake website.

### 4. **Secret Leakage Attack**

If the shared secret is stolen → attacker can generate valid codes.

---

## Defenses

* **Time synchronization** using NTP
* **Rate limiting & lockouts**
* **Short validity windows** (30 seconds or less)
* **Store secrets securely**:

  * KMS / Vault
  * Encrypted storage
* **Use MFA** — TOTP alone is not enough

---

## Implementing TOTP in Python (pyotp)

### Install

```
pip install pyotp
```

### Generate a secret

```python
import pyotp
secret = pyotp.random_base32()
print(secret)
```

### Generate TOTP code

```python
import pyotp
totp = pyotp.TOTP(secret)
print(totp.now())
```

### Verify code

```python
print(totp.verify("123456"))
```

---

## Generate QR Code for Google Authenticator

```python
import pyotp
import qrcode

secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name="user@example.com", issuer_name="MyApp")

img = qrcode.make(uri)
img.save("totp.png")
```

---

## Example Attack (Educational Only)

### Simple Brute Force Demo

```python
import pyotp, time

secret = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(secret)

code = totp.now()
print("Real code:", code)

for guess in range(0, 1000000):
    if f"{guess:06d}" == code:
        print("Found it:", guess)
        break
```

⚠️ **Educational use only — unauthorized use is illegal.**

---

## Protecting Against Brute Force

* **Rate limiting** attempts per minute
* **Temporary lockouts** on repeated failure
* **Reliable NTP time sync** for accurate code generation
* **Secure secret storage** with encryption

---

## Example Python Project

A small secure TOTP authentication service using FastAPI:

* User registration with secret generation
* QR code provisioning
* Login endpoint verifying TOTP

---

## Useful Links

* [RFC 6238 (TOTP standard)](https://datatracker.ietf.org/doc/html/rfc6238)
* [pyotp GitHub](https://github.com/pyauth/pyotp)
* [HOTP standard (RFC 4226)](https://datatracker.ietf.org/doc/html/rfc4226)
* [How TOTP works (tutorial)](https://www.youtube.com/watch?v=46AKWNOJ3-Y)

---

## Summary

TOTP is a widely used, standard, and relatively simple authentication mechanism. It is secure when implemented properly but requires careful handling of time synchronization, secret storage, and protection against phishing and brute‑force attacks.

This document includes all theory, examples, attack demonstrations, and protection strategies needed for research and implementation.
