"""
SecureNet AI — Cryptographic & Security Utilities
Provides native bcrypt password hashing, token generation, and cryptographic constants.
"""

from datetime import datetime, timedelta
from typing import Optional
import bcrypt
from jose import jwt

SECRET_KEY = "SECURENET_SUPER_SECRET_ENTERPRISE_KEY_JWT_2026_NIDS_NIPS"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30  # 30 days


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain text password against an existing bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8")[:72],
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Generates a secure bcrypt hash for a plain text password."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8")[:72], salt).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Encodes identity claims into a signed HS256 JWT token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
