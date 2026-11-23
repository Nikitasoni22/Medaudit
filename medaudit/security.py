"""Password hashing, password policy and session tokens (shared by both services)."""
from __future__ import annotations

import hashlib
import hmac
import secrets

_DUMMY_SALT = b"\x5a" * 16


def hash_password(password: str, iters: int) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return f"pbkdf2${iters}${salt.hex()}${h.hex()}"


def verify_password(password: str, stored: str | None, default_iters: int) -> bool:
    """Constant-ish time: always performs a PBKDF2 even for unknown users."""
    try:
        _, iters_s, salt_hex, hash_hex = (stored or "").split("$")
        iters, salt, expect = int(iters_s), bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
        known = True
    except ValueError:
        iters, salt, expect, known = default_iters, _DUMMY_SALT, b"\x00" * 32, False
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return hmac.compare_digest(got, expect) and known


def password_problem(pw: str) -> str | None:
    if len(pw) < 10:
        return "password must be at least 10 characters"
    if len(pw) > 200:
        return "password too long"
    classes = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                   any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    if classes < 3:
        return "use at least three of: lowercase, uppercase, digits, symbols"
    return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    """Only the SHA-256 of a session token is stored, so a DB leak yields no usable sessions."""
    return hashlib.sha256(token.encode()).hexdigest()
