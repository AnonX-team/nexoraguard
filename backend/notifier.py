"""
NexoraGuard — Windows Native Notifications
Uses plyer (wraps WinRT/win32 toast notifications).
All calls are fire-and-forget in a daemon thread so they never block the scanner.
"""
import sys
import os
import time
import logging
import threading

logger = logging.getLogger(__name__)

# ── Dedup state ───────────────────────────────────────────────────────────────
# Maps severity string → last notification timestamp.
# Prevents spamming the user if the scanner fires every 15 s.
_last_notified: dict[str, float] = {}
_COOLDOWN = 300.0   # 5 minutes between same-severity notifications


def _icon_path() -> str | None:
    if getattr(sys, "frozen", False):
        # onedir: bundled inside _internal/ (sys._MEIPASS)
        p = os.path.join(sys._MEIPASS, "logo.ico")
        if not os.path.exists(p):
            p = os.path.join(os.path.dirname(sys.executable), "logo.ico")
    else:
        p = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logo.ico"
        )
    return p if os.path.exists(p) else None


def _send(title: str, message: str, icon: str | None):
    """Run in a daemon thread — never blocks the caller."""
    try:
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name="NexoraGuard",
            app_icon=icon,
            timeout=8,
        )
    except Exception as e:
        logger.debug(f"plyer notification failed: {e}")


def notify_threat(risk_level: str, summary: str):
    """
    Fire a Windows toast notification for a detected threat.

    Args:
        risk_level: "CRITICAL" | "HIGH" | "MEDIUM"
        summary:    Short description shown in the notification body.
    """
    severity = risk_level.upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM"):
        return

    # Cooldown check
    now = time.monotonic()
    if now - _last_notified.get(severity, 0) < _COOLDOWN:
        return
    _last_notified[severity] = now

    icons = {
        "CRITICAL": "🚨",
        "HIGH":     "⚠️",
        "MEDIUM":   "🔔",
    }
    titles = {
        "CRITICAL": "NexoraGuard — CRITICAL THREAT DETECTED",
        "HIGH":     "NexoraGuard — High Risk Alert",
        "MEDIUM":   "NexoraGuard — Medium Risk Detected",
    }
    title   = titles[severity]
    message = f"{icons[severity]} {summary[:200]}"  # Windows cap ~256 chars
    icon    = _icon_path()

    t = threading.Thread(target=_send, args=(title, message, icon), daemon=True)
    t.start()
    logger.info(f"Threat notification dispatched — {severity}: {summary[:80]}")


def notify_startup(api_key_loaded: bool):
    """Optional startup toast — shown once when EXE first starts."""
    try:
        from plyer import notification
        if api_key_loaded:
            msg = "AI protection active. Dashboard: http://127.0.0.1:8000"
        else:
            msg = "Running in rule-only mode. Open Dashboard → Settings to add AI key."
        t = threading.Thread(
            target=_send,
            args=("NexoraGuard is running", msg, _icon_path()),
            daemon=True
        )
        t.start()
    except Exception:
        pass
