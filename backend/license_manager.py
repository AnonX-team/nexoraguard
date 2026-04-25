"""
NexoraGuard — License Manager
Validates device-locked license keys for Phase 1 B2C rollout.

License key format (v2 — simplified):
    XXXX-XXXX-XXXX-XXXX  (16 uppercase hex chars, dash-grouped for readability)
    Raw 16-char format (no dashes) is also accepted.

Generation (admin side):
    python generate_key.py
    -> Enter customer Device ID -> outputs 16-char key

Validation (agent side):
    SHA256(hardware_id + SALT)[:16].upper() == key_in_license_txt

The key is device-locked: recomputing the hash on a different machine
produces a different result, so the key is non-transferable.
"""

import sys
import hashlib
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Shared secret — MUST match generate_key.py exactly ───────────────────────
# Keep this value private. Changing it invalidates all previously issued keys.
LICENSE_SALT = "NexoraGuard_Secure_2026"

# Edition returned for all valid v2 keys (B2C Phase 1 = LITE)
_DEFAULT_EDITION = "LITE"

EDITION_FEATURES = {
    "LITE": {
        "description": "Consumer Lite",
        "max_processes_shown": 50,
        "ai_scans": True,
        "network_monitor": False,
        "bruteforce": False,
        "registry_monitor": True,
        "file_integrity": True,
    },
    "PRO": {
        "description": "Professional",
        "max_processes_shown": 500,
        "ai_scans": True,
        "network_monitor": True,
        "bruteforce": True,
        "registry_monitor": True,
        "file_integrity": True,
    },
}


# ── License file location ─────────────────────────────────────────────────────
def _find_license_path() -> Path:
    if getattr(sys, "frozen", False):
        # EXE mode — license.txt must sit beside NexoraGuard.exe
        return Path(sys.executable).parent / "license.txt"
    # Dev mode — project root (one level above backend/)
    return Path(__file__).parent.parent / "license.txt"


LICENSE_FILE = _find_license_path()


# ── Core validation ───────────────────────────────────────────────────────────

def _compute_expected_key(hardware_id: str) -> str:
    """
    Deterministic 16-char key for a given hardware ID.
    This is what generate_key.py computes on the admin side.
    """
    clean_id = hardware_id.strip().upper().replace("-", "")
    raw      = clean_id + LICENSE_SALT
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()


def is_license_valid(key: str) -> tuple[bool, str]:
    """
    Validate a 16-character license key against THIS machine's hardware ID.

    Returns:
        (True,  "License valid")   — key is genuine and for this device
        (False, "reason string")   — key is invalid; reason is human-readable
    """
    from utils.identity import get_hardware_id

    key = key.strip().upper().replace("-", "")   # accept XXXX-XXXX-XXXX-XXXX or flat 16 chars

    # Basic format check — must be exactly 16 uppercase hex characters after stripping dashes
    if len(key) != 16 or not all(c in "0123456789ABCDEF" for c in key):
        return False, (
            "Invalid key format. The license key must be 16 hex characters "
            "(e.g. XXXX-XXXX-XXXX-XXXX). "
            "Contact us on WhatsApp: +92 342 4217045"
        )

    # Recompute the expected key for this machine and compare
    try:
        hardware_id  = get_hardware_id()
        expected_key = _compute_expected_key(hardware_id)
    except Exception as e:
        logger.error(f"Hardware ID computation failed: {e}")
        return False, "Could not read hardware ID. Please restart NexoraGuard as Administrator."

    if key != expected_key:
        logger.warning(f"License key mismatch for device {hardware_id[:8]}...")
        return False, (
            "This license key is not valid for this device. "
            "Send your Device ID to WhatsApp +92 342 4217045 to get the correct key."
        )

    logger.info(f"License key validated for device {hardware_id[:8]}...")
    return True, "License valid — NexoraGuard activated"


def get_license_info() -> dict:
    """
    Read license.txt and return a full status dict consumed by /license endpoint.
    Always returns a valid dict — never raises.
    """
    # Safely get the hardware display ID (never raises)
    try:
        from utils.identity import get_display_id
        display_id = get_display_id()
    except Exception as e:
        logger.error(f"get_display_id failed: {e}")
        display_id = "Error reading Device ID — restart as Administrator"

    result = {
        "device_id":       display_id,
        "license_file":    str(LICENSE_FILE),
        "licensed":        False,
        "edition":         None,
        "edition_features": None,
        "key_preview":     None,
        "message":         "",
        "checked_at":      datetime.now().isoformat(),
    }

    # ── No license.txt ────────────────────────────────────────────────────────
    if not LICENSE_FILE.exists():
        result["message"] = (
            "No license.txt found. "
            "Send your Device ID (shown above) to WhatsApp +92 342 4217045. "
            "Then create license.txt in the same folder as NexoraGuard.exe and paste your key inside."
        )
        return result

    # ── Empty file ────────────────────────────────────────────────────────────
    try:
        raw_key = LICENSE_FILE.read_text(encoding="utf-8").strip()
    except Exception as e:
        result["message"] = f"Could not read license.txt: {e}"
        return result

    if not raw_key:
        result["message"] = (
            "license.txt is empty. Paste your 16-character license key inside the file."
        )
        return result

    # ── Mask key for display (show first 4 and last 4 chars only) ────────────
    if len(raw_key) >= 8:
        result["key_preview"] = raw_key[:4] + "..." + raw_key[-4:]
    else:
        result["key_preview"] = raw_key

    # ── Validate ──────────────────────────────────────────────────────────────
    valid, msg = is_license_valid(raw_key)
    result["message"] = msg

    if valid:
        result["licensed"]         = True
        result["edition"]          = _DEFAULT_EDITION
        result["edition_features"] = EDITION_FEATURES[_DEFAULT_EDITION]

    return result


def get_edition() -> str:
    """Quick helper — returns edition string or 'NONE' if unlicensed."""
    return get_license_info().get("edition") or "NONE"
