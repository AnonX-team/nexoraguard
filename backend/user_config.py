"""
NexoraGuard — User Configuration Manager
Stores user preferences (API key, etc.) encrypted with the machine's hardware ID.

Encryption: Fernet (AES-128 CBC + HMAC) — symmetric, derived from hardware fingerprint.
The encrypted config file is machine-locked: copying it to another PC produces garbage.

File location: user_config.json beside the .exe (or project root in dev mode).
"""
import os
import sys
import json
import base64
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _config_path() -> Path:
    # Frozen EXE: store in AppData so settings survive EXE updates
    # Dev mode: project root (convenient for development)
    if getattr(sys, "frozen", False):
        appdata = os.environ.get("APPDATA") or str(Path.home())
        config_dir = Path(appdata) / "NexoraCyberTech" / "NexoraGuard"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "user_config.json"
    return Path(__file__).parent.parent / "user_config.json"


def _get_fernet():
    """Build a Fernet cipher keyed to this machine's hardware ID."""
    try:
        from cryptography.fernet import Fernet
        from utils.identity import get_hardware_id
        hw = get_hardware_id()[:32]           # 32 hex chars = 32 bytes
        fernet_key = base64.urlsafe_b64encode(hw.encode("utf-8")[:32])
        return Fernet(fernet_key)
    except ImportError as e:
        raise RuntimeError(f"Encryption unavailable — missing dependency: {e}") from e


def _load_raw() -> dict:
    path = _config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_raw(data: dict):
    _config_path().write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── Public API ────────────────────────────────────────────────────────────────

def get_api_key() -> str:
    """
    Return the user's stored API key, decrypted.
    Returns empty string if no key is stored or decryption fails.
    """
    data = _load_raw()
    encrypted = data.get("api_key_enc")
    if not encrypted:
        return ""
    try:
        return _get_fernet().decrypt(encrypted.encode()).decode()
    except Exception as e:
        logger.warning(f"Could not decrypt stored API key: {e}")
        return ""


def save_api_key(api_key: str):
    """Encrypt and persist the user's API key."""
    api_key = api_key.strip()
    data = _load_raw()
    if api_key:
        data["api_key_enc"] = _get_fernet().encrypt(api_key.encode()).decode()
    else:
        data.pop("api_key_enc", None)
    _save_raw(data)
    logger.info("User API key saved (encrypted)")


def remove_api_key():
    """Remove the stored API key."""
    data = _load_raw()
    data.pop("api_key_enc", None)
    _save_raw(data)
    logger.info("User API key removed")


def has_api_key() -> bool:
    return bool(get_api_key())


def get_key_preview() -> str:
    """Returns a masked preview like 'gsk_Ab12...xyz9' for display."""
    key = get_api_key()
    if not key:
        return None
    if len(key) >= 12:
        return key[:8] + "..." + key[-4:]
    return key[:4] + "..."
