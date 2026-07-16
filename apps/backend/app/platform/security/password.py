"""
Password hashing utilities.

Uses the `bcrypt` library directly rather than passlib. passlib 1.7.4's
bcrypt backend runs an internal self-test against bcrypt >= 4.1 that
raises ValueError ("password cannot be longer than 72 bytes") before a
single real password is ever hashed - it is unrelated to the length of
the user's own password. Calling bcrypt directly avoids that
incompatibility entirely and removes an unmaintained dependency.
"""

import re

import bcrypt

from app.config.constants import PASSWORD_MIN_LENGTH

# bcrypt only uses the first 72 bytes of the input; anything beyond that
# is silently ignored by the algorithm itself, so we cap accepted
# passwords at 72 bytes and reject longer ones explicitly rather than
# truncating silently.
_BCRYPT_MAX_BYTES = 72

_PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).+$"
)


def hash_password(password: str) -> str:
    encoded = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    encoded = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    try:
        return bcrypt.checkpw(encoded, password_hash.encode("utf-8"))
    except ValueError:
        # Malformed / foreign hash format.
        return False


def validate_password_policy(password: str) -> bool:
    """
    Enforce FRS FR-001 password policy:
    minimum 12 characters, upper, lower, number, special character.
    """

    if len(password) < PASSWORD_MIN_LENGTH:
        return False

    if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
        return False

    return bool(_PASSWORD_PATTERN.match(password))
