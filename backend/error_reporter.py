"""
NexoraGuard — Automatic Error Reporter
Sends critical crash reports asynchronously to the Nexora central backend.

Design:
  - Non-blocking: uses a background thread so crashes never slow the main app
  - Deduplicated: same error won't spam the server (60s cooldown per error type)
  - Fails silently: if the central server is down, the error is only logged locally
  - Enriched: attaches device ID, edition, OS version, and timestamp automatically
"""

import threading
import hashlib
import logging
import platform
import traceback
from datetime import datetime, timedelta
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

# Central backend URL — replace with your production server endpoint
_REPORT_URL = "https://api.nexoracybertech.com/v1/crash-report"

# Fallback: also POST to a local log endpoint (localhost, for dev testing)
_REPORT_URL_DEV = "http://127.0.0.1:8080/internal/crash-report"

# Minimum seconds between identical error reports (prevents spam)
_DEDUP_COOLDOWN_SECONDS = 60

# Request timeout — never block the app waiting for the server
_REQUEST_TIMEOUT = 5


# ── State ─────────────────────────────────────────────────────────────────────

_last_sent: dict[str, datetime] = {}   # error_hash → last sent time
_lock = threading.Lock()


# ── Core ──────────────────────────────────────────────────────────────────────

def _error_hash(error_message: str) -> str:
    """Stable 12-char identifier for a given error type (for deduplication)."""
    return hashlib.sha256(error_message.encode()).hexdigest()[:12]


def _build_payload(error_message: str, context: Optional[str] = None) -> dict:
    """Build the full crash report payload."""
    from utils.identity import get_hardware_id
    from license_manager import get_edition

    try:
        device_id = get_hardware_id()[:8]   # only the short ID for privacy
        edition   = get_edition()
    except Exception:
        device_id = "UNKNOWN"
        edition   = "UNKNOWN"

    return {
        "device_id":    device_id,
        "edition":      edition,
        "app_version":  "1.0.0",
        "os":           f"{platform.system()} {platform.release()} {platform.version()[:30]}",
        "python":       platform.python_version(),
        "error":        error_message[:2000],           # truncate large stack traces
        "context":      context or "unspecified",
        "timestamp":    datetime.utcnow().isoformat() + "Z",
    }


def _send(payload: dict):
    """
    Internal: actually POST the report.
    Tries the production URL first, falls back to dev endpoint.
    Runs in a daemon thread — never raises exceptions.
    """
    for url in [_REPORT_URL, _REPORT_URL_DEV]:
        try:
            resp = requests.post(url, json=payload, timeout=_REQUEST_TIMEOUT)
            if resp.status_code < 400:
                logger.debug(f"Crash report sent to {url} — status {resp.status_code}")
                return
        except requests.exceptions.ConnectionError:
            # Production server unreachable — try next
            continue
        except Exception as e:
            logger.debug(f"Error reporter failed for {url}: {e}")
            continue

    # Both endpoints failed — error is already logged locally, that's fine
    logger.debug("Crash report could not be delivered (server unreachable). Logged locally.")


# ── Public API ────────────────────────────────────────────────────────────────

def report_error(
    error_message: str,
    context: Optional[str] = None,
    exc: Optional[BaseException] = None,
):
    """
    Report a critical crash to the Nexora central backend.

    Non-blocking — fires a daemon thread and returns immediately.
    Identical errors are deduplicated with a 60-second cooldown.

    Args:
        error_message:  Short description or the str(exception)
        context:        Which module/function caught the error (e.g. "background_scanner")
        exc:            The actual exception object (to extract full traceback)

    Usage:
        try:
            do_something_dangerous()
        except Exception as e:
            report_error(str(e), context="my_module.my_function", exc=e)
            raise  # or handle locally
    """
    # Build full message (include traceback if exception provided)
    if exc is not None:
        full_message = (
            f"{error_message}\n\n"
            f"Traceback:\n{''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))}"
        )
    else:
        full_message = error_message

    err_hash = _error_hash(full_message)

    # Deduplication check
    with _lock:
        last = _last_sent.get(err_hash)
        if last and datetime.utcnow() - last < timedelta(seconds=_DEDUP_COOLDOWN_SECONDS):
            logger.debug(f"Error report suppressed (duplicate within cooldown): {err_hash}")
            return
        _last_sent[err_hash] = datetime.utcnow()

    # Log locally regardless
    logger.error(f"[CRASH REPORT] context={context or 'unknown'} | {error_message[:200]}")

    # Send in background — completely non-blocking
    payload = _build_payload(full_message, context)
    thread  = threading.Thread(target=_send, args=(payload,), daemon=True, name="ErrorReporter")
    thread.start()
