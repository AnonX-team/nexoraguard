"""
NexoraGuard — JWT Authentication
Handles login, token validation, and password management.
Default credentials: admin / nexora@2024

Password hashing: PBKDF2-HMAC-SHA256 via stdlib hashlib (no passlib needed).
JWT: python-jose with HS256.
"""
import json
import secrets
import hashlib
import hmac
import os
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import HTTPException, status
from jose import JWTError, jwt

# ── Paths ──────────────────────────────────────────────────────────────────────
_DIR = Path(__file__).parent
_CREDS_FILE = _DIR / "auth_credentials.json"
_SECRET_FILE = _DIR / "auth_secret.key"

# ── Config ─────────────────────────────────────────────────────────────────────
_TOKEN_EXPIRE_HOURS = 8
_ALGORITHM = "HS256"
_PBKDF2_ITERS = 390_000  # OWASP recommended minimum for SHA-256

# ── Password Hashing (PBKDF2-HMAC-SHA256) ────────────────────────────────────
def _hash_password(password: str) -> str:
    """Hash password with PBKDF2-HMAC-SHA256. Returns 'pbkdf2$salt$hash'."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERS)
    return f"pbkdf2${salt}${dk.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    """Constant-time verify password against stored hash."""
    try:
        _, salt, stored_hex = stored.split("$", 2)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERS)
        return hmac.compare_digest(dk.hex(), stored_hex)
    except Exception:
        return False

# ── JWT Secret (auto-generated, persisted) ────────────────────────────────────
def _get_jwt_secret() -> str:
    if _SECRET_FILE.exists():
        return _SECRET_FILE.read_text().strip()
    secret = secrets.token_urlsafe(48)
    _SECRET_FILE.write_text(secret)
    return secret

JWT_SECRET = _get_jwt_secret()

# ── Credentials file ──────────────────────────────────────────────────────────
def _load_creds() -> dict:
    """Load credentials, creating defaults on first run."""
    if not _CREDS_FILE.exists():
        default = {
            "username": "admin",
            "password_hash": _hash_password("nexora@2024"),
            "full_name": "Administrator",
            "role": "admin"
        }
        _CREDS_FILE.write_text(json.dumps(default, indent=2))
        return default
    return json.loads(_CREDS_FILE.read_text())

def _save_creds(creds: dict):
    _CREDS_FILE.write_text(json.dumps(creds, indent=2))

# ── Token Operations ──────────────────────────────────────────────────────────
def create_token(username: str) -> dict:
    """Create JWT access token, return token + expiry info."""
    expire = datetime.utcnow() + timedelta(hours=_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": username,
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=_ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": _TOKEN_EXPIRE_HOURS * 3600,
    }

def verify_token(token: str) -> str:
    """Validate Bearer token, return username. Raises 401 on failure."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[_ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return username
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired or invalid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

# ── Auth Operations ───────────────────────────────────────────────────────────
def login(username: str, password: str) -> dict:
    """Verify credentials and return token dict."""
    creds = _load_creds()
    if username != creds["username"] or not _verify_password(password, creds["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    return create_token(username)

def change_password(username: str, old_password: str, new_password: str):
    """Change password after verifying old one."""
    creds = _load_creds()
    if username != creds["username"] or not _verify_password(old_password, creds["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    creds["password_hash"] = _hash_password(new_password)
    _save_creds(creds)
    return {"message": "Password changed successfully"}

def get_user_info(username: str) -> dict:
    """Return public profile (no password hash)."""
    creds = _load_creds()
    return {
        "username": creds["username"],
        "full_name": creds.get("full_name", "Administrator"),
        "role": creds.get("role", "admin"),
    }
