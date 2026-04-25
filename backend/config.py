import os
import sys
from dotenv import load_dotenv

# Frozen EXE: .env sits beside NexoraGuard.exe in dist/
# Dev mode:   .env sits at project root (one level above backend/)
if getattr(sys, "frozen", False):
    _env_path = os.path.join(os.path.dirname(sys.executable), ".env")
else:
    _env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")

load_dotenv(_env_path, override=False)   # override=False: env vars already set win

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# ── Product Mode ──────────────────────────────────────────────────────────────
# "CONSUMER" — Phase 1 Lite (hides Network + Brute Force tabs in UI)
# "ENTERPRISE" — Full feature set (all tabs visible)
# Set via .env: ENV_MODE=ENTERPRISE
ENV_MODE = os.getenv("ENV_MODE", "CONSUMER").upper()

# ── Detection thresholds ──────────────────────────────────────────────────────
FAILED_LOGIN_THRESHOLD = 5       # Alert after N failed logins
SCAN_INTERVAL_SECONDS = 15       # How often to scan logs
LOG_FETCH_COUNT = 50             # How many recent events to fetch

# ── Risk levels ───────────────────────────────────────────────────────────────
RISK_LEVELS = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 10,
    "SAFE": 0
}
