from enum import Enum, unique

@unique
class ServerStatus(Enum):
    # Success
    OK = 200              # Login success / TOTP required / general success
    CREATED = 201         # Registration successful

    # Client errors
    BAD_REQUEST = 400     # Missing fields / invalid input
    UNAUTHORIZED = 401    # Invalid credentials / invalid TOTP / not authenticated
    NOT_FOUND = 404       # Endpoint not found / user not found
    CONFLICT = 409        # Username already exists

    # Security / protection
    PERMANENT_LOCKOUT = 423   # Account permanently locked
    TOO_MANY_REQUESTS = 429   # CAPTCHA required / rate limit lockout

    # Server error
    INTERNAL_ERROR = 500      # Unhandled server error

# used for automation/test_users_generator.py and config.json
class HashingAlgorithm(Enum):
    ARGON2 = 'Argon2' # 0
    BCRYPT = 'bcrypt' # 1
    SHA256_SALT = 'SHA-256 + SALT' # 2