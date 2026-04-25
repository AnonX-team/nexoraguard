"""
NexoraGuard — Central Configuration Manager
All persistent data lives in %APPDATA%/NexoraCyberTech/NexoraGuard/
so settings survive EXE reinstalls and are never stored inside Program Files.
"""
import os
import sys
import json
import base64
import logging
from pathlib import Path

_APP_VENDOR = "NexoraCyberTech"
_APP_NAME   = "NexoraGuard"


# ── Directory helpers ─────────────────────────────────────────────────────────

def get_config_dir() -> Path:
    """Returns (and creates) the AppData config directory."""
    appdata = os.environ.get("APPDATA") or str(Path.home())
    d = Path(appdata) / _APP_VENDOR / _APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_config_path() -> Path:
    return get_config_dir() / "config.json"


def get_log_path() -> Path:
    return get_config_dir() / "nexoraguard.log"


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_file_logging(level=logging.INFO):
    """
    Route all logging to the AppData log file.
    Call once from launcher.py before anything else starts.
    Safe to call multiple times — adds handler only once.
    """
    root = logging.getLogger()
    if any(isinstance(h, logging.FileHandler) for h in root.handlers):
        return   # already configured

    log_path = get_log_path()
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    ))
    root.setLevel(level)
    root.addHandler(fh)


# ── Config load / save ────────────────────────────────────────────────────────

def load_config() -> dict:
    path = get_config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(data: dict):
    get_config_path().write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── API key — encrypted with hardware ID ─────────────────────────────────────

def _get_fernet():
    try:
        from cryptography.fernet import Fernet
        from utils.identity import get_hardware_id
        hw = get_hardware_id()[:32]
        return Fernet(base64.urlsafe_b64encode(hw.encode("utf-8")[:32]))
    except ImportError as e:
        raise RuntimeError(f"Encryption unavailable — missing dependency: {e}") from e


def get_api_key() -> str:
    """Return the decrypted API key, or '' if not set."""
    enc = load_config().get("api_key_enc")
    if not enc:
        return ""
    try:
        return _get_fernet().decrypt(enc.encode()).decode()
    except Exception as e:
        logging.getLogger(__name__).warning(f"API key decrypt failed: {e}")
        return ""


def save_api_key(key: str):
    key = key.strip()
    cfg = load_config()
    if key:
        cfg["api_key_enc"] = _get_fernet().encrypt(key.encode()).decode()
    else:
        cfg.pop("api_key_enc", None)
    save_config(cfg)
    logging.getLogger(__name__).info("API key saved to AppData config")


def remove_api_key():
    cfg = load_config()
    cfg.pop("api_key_enc", None)
    save_config(cfg)


def has_api_key() -> bool:
    return bool(get_api_key())


def get_key_preview() -> str:
    key = get_api_key()
    if not key:
        return None
    return (key[:8] + "..." + key[-4:]) if len(key) >= 12 else key[:4] + "..."
