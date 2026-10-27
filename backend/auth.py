"""
SecureNet AI — Authentication & RBAC Engine (Supabase Auth Integration)
Validates incoming Supabase GoTrue JWT Bearer tokens using the Supabase JWT Secret,
extracts authenticated operator claims (sub, email, role, metadata), and enforces
strict Role-Based Access Control (RBAC) across FastAPI endpoints.
"""

import os
from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

import base64
import json
import urllib.request
import urllib.error

from models import User
from database import get_db
from security import SECRET_KEY, ALGORITHM

# Supabase URL & JWT Secret (configured via environment)
SUPABASE_URL = os.getenv("SUPABASE_URL", os.getenv("VITE_SUPABASE_URL", "https://yztyzrckpunggsckqdvm.supabase.co"))
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", os.getenv("SECRET_KEY", "SECURENET_SUPER_SECRET_ENTERPRISE_KEY_JWT_2026_NIDS_NIPS"))

# OAuth2 password bearer scheme pointing to the login endpoint (auto_error=False for custom 401 handling)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

_jwks_cache: Optional[dict] = None


def get_supabase_jwks() -> Optional[dict]:
    """Retrieves and caches the Supabase public JWKS for verifying ES256/RS256 tokens."""
    global _jwks_cache
    if _jwks_cache:
        return _jwks_cache
    if not SUPABASE_URL:
        return None
    try:
        endpoint = SUPABASE_URL.rstrip("/") + "/auth/v1/.well-known/jwks.json"
        req = urllib.request.Request(endpoint, headers={"User-Agent": "SecureNetAI/1.0"})
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status == 200:
                _jwks_cache = json.loads(response.read().decode("utf-8"))
                return _jwks_cache
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError):
        pass
    return None


def decode_supabase_jwt(token: str) -> dict:
    """
    Decodes and validates a Supabase JWT Bearer token.
    Supports:
    1. Modern Supabase Asymmetric ECDSA tokens (ES256 via public JWKS endpoint)
    2. Symmetric HS256 tokens (literal SUPABASE_JWT_SECRET or base64-decoded raw bytes)
    3. RS256 RSA signing keys
    4. Local development SECRET_KEY fallback
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate Supabase credentials or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception

    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "HS256")
    except Exception:
        alg = "HS256"

    # 1. Asymmetric verification via Supabase JWKS (for ES256 / RS256 tokens)
    if alg in ["ES256", "RS256"]:
        jwks = get_supabase_jwks()
        if jwks:
            try:
                payload = jwt.decode(
                    token,
                    jwks,
                    algorithms=[alg],
                    options={"verify_aud": False}
                )
                return payload
            except Exception:
                pass

    # 2. Symmetric verification with literal SUPABASE_JWT_SECRET (HS256 / RS256)
    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256", "RS256"],
            options={"verify_aud": False}
        )
        return payload
    except Exception:
        pass

    # 3. Symmetric verification with Base64-decoded SUPABASE_JWT_SECRET
    try:
        decoded_bytes = base64.b64decode(SUPABASE_JWT_SECRET)
        payload = jwt.decode(
            token,
            decoded_bytes,
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
        return payload
    except Exception:
        pass

    # 4. Backward compatibility fallback: verify with local SECRET_KEY
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_aud": False}
        )
        return payload
    except Exception:
        raise credentials_exception


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI security dependency to validate incoming Supabase JWT Bearer token
    and resolve or synchronize the authenticated operator User record.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate Supabase credentials or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    payload = decode_supabase_jwt(token)
    user_id: Optional[str] = payload.get("sub")
    email: str = payload.get("email", "")

    if not user_id and not email:
        raise credentials_exception

    # Extract user metadata and roles configured in Supabase Auth
    user_metadata = payload.get("user_metadata") or {}
    app_metadata = payload.get("app_metadata") or {}

    username = (
        user_metadata.get("username")
        or user_metadata.get("full_name")
        or (email.split("@")[0] if email else None)
        or f"operator_{user_id[:8]}"
    )

    # Determine assigned RBAC role (admin, analyst, employee)
    raw_role = (
        user_metadata.get("role")
        or app_metadata.get("role")
        or payload.get("role")
    )

    if raw_role in ["admin", "analyst", "employee"]:
        role = raw_role
    else:
        # Default role determination based on username/email identifiers
        uname_lower = username.lower()
        email_lower = email.lower()
        if "admin" in uname_lower or "admin" in email_lower:
            role = "admin"
        elif "analyst" in uname_lower or "analyst" in email_lower:
            role = "analyst"
        elif "employee" in uname_lower or "employee" in email_lower:
            role = "employee"
        else:
            role = "admin"  # Default authenticated operator role

    # Resolve or synchronize operator record in database
    user = db.query(User).filter(
        (User.username == username) | (User.username == email)
    ).first()

    if not user:
        user = User(
            username=username,
            hashed_password="",  # Auth delegated to Supabase GoTrue
            role=role
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
        except SQLAlchemyError as err:
            db.rollback()
            print(f"[Supabase Auth DB Notice] Could not insert new user record: {err}")
            user = db.query(User).filter(User.username == username).first()
            if not user:
                user = User(id=1, username=username, hashed_password="", role=role)
    else:
        if role and user.role != role:
            user.role = role
            try:
                db.commit()
            except SQLAlchemyError as err:
                db.rollback()
                print(f"[Supabase Auth DB Notice] Could not update user role: {err}")

    return user


def require_role(allowed_roles: List[str]):
    """
    Role-Based Access Control (RBAC) dependency factory.
    Enforces that the authenticated Supabase user has one of `allowed_roles`.
    """
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges. Required: {allowed_roles}, Current: '{current_user.role}'."
            )
        return current_user
    return role_checker
