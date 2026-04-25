"""
Process Whitelist / Exception System
Ensures NexoraGuard NEVER kills essential Windows or user-defined processes.
Three-tier protection:
  TIER 1 — Hardcoded critical OS processes (cannot be overridden)
  TIER 2 — Common safe processes (can be removed by admin)
  TIER 3 — User-defined whitelist (stored in whitelist.json)
"""
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
WHITELIST_FILE = Path(__file__).parent / "whitelist.json"

# ── TIER 1: Critical OS — NEVER kill (hardcoded, immutable) ───────────────────
CRITICAL_OS = frozenset({
    # Core Windows kernel & session
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "lsass.exe", "lsaiso.exe", "services.exe",

    # Service Control Manager & subsystems
    "svchost.exe", "spoolsv.exe", "rpcss.exe", "dcomlaunch.exe",

    # Security subsystems — killing these crashes Windows
    "securityhealthservice.exe", "msseces.exe", "msmpeng.exe", "nissrv.exe",

    # Driver frameworks
    "dwm.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",

    # Session/shell
    "explorer.exe", "userinit.exe", "ctfmon.exe",

    # NexoraGuard itself
    "nexoraguard.exe", "python.exe", "pythonw.exe", "uvicorn.exe",
})

# ── TIER 2: Common safe processes (AI should not flag these) ──────────────────
COMMON_SAFE = frozenset({
    # Browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "iexplore.exe", "safari.exe",

    # Dev tools
    "code.exe", "devenv.exe", "idea64.exe", "studio64.exe", "androidstudio64.exe",
    "pycharm64.exe", "git.exe", "node.exe", "npm.exe",

    # Office
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "acrobat.exe", "acrord32.exe",

    # System utilities
    "taskmgr.exe", "regedit.exe", "mmc.exe", "msiexec.exe", "wuauclt.exe",
    "searchindexer.exe", "antimalware service executable",

    # Communication
    "teams.exe", "slack.exe", "discord.exe", "zoom.exe", "skype.exe",
    "telegram.exe", "whatsapp.exe",
})


def load_user_whitelist() -> set:
    """Load user-defined whitelist from JSON file."""
    if not WHITELIST_FILE.exists():
        return set()
    try:
        with open(WHITELIST_FILE) as f:
            data = json.load(f)
        return set(p.lower() for p in data.get("processes", []))
    except Exception as e:
        logger.error(f"Whitelist load error: {e}")
        return set()


def save_user_whitelist(processes: list[str]):
    """Save user-defined whitelist."""
    with open(WHITELIST_FILE, "w") as f:
        json.dump({"processes": list(set(p.lower() for p in processes))}, f, indent=2)


def add_to_whitelist(process_name: str) -> dict:
    """Add a process to user whitelist."""
    current = list(load_user_whitelist())
    name = process_name.lower()
    if name in current:
        return {"success": False, "message": f"{name} already in whitelist"}
    current.append(name)
    save_user_whitelist(current)
    return {"success": True, "message": f"{name} added to whitelist"}


def remove_from_whitelist(process_name: str) -> dict:
    """Remove a process from user whitelist."""
    name = process_name.lower()
    if name in CRITICAL_OS:
        return {"success": False, "message": f"{name} is a critical OS process — cannot remove from protection"}
    current = list(load_user_whitelist())
    if name not in current:
        return {"success": False, "message": f"{name} not found in user whitelist"}
    current.remove(name)
    save_user_whitelist(current)
    return {"success": True, "message": f"{name} removed from whitelist"}


def is_protected(process_name: str) -> dict:
    """
    Check if a process is protected.
    Returns: {protected: bool, tier: str, reason: str}
    """
    name = process_name.lower().strip()

    if name in CRITICAL_OS:
        return {
            "protected": True,
            "tier": "CRITICAL",
            "reason": f"'{name}' is a critical Windows OS process — killing it would crash the system"
        }

    if name in COMMON_SAFE:
        return {
            "protected": True,
            "tier": "SAFE",
            "reason": f"'{name}' is in the common safe process list"
        }

    user_wl = load_user_whitelist()
    if name in user_wl:
        return {
            "protected": True,
            "tier": "USER",
            "reason": f"'{name}' is in your custom whitelist"
        }

    return {"protected": False, "tier": None, "reason": None}


def safe_kill_check(pid: int, process_name: str) -> dict:
    """
    Final safety check before killing any process.
    Returns: {allowed: bool, message: str}
    """
    check = is_protected(process_name)

    if check["protected"]:
        logger.warning(f"Kill BLOCKED: {process_name} (PID {pid}) — {check['reason']}")
        return {
            "allowed": False,
            "message": f"Cannot kill '{process_name}': {check['reason']}",
            "tier": check["tier"]
        }

    logger.info(f"Kill ALLOWED: {process_name} (PID {pid})")
    return {"allowed": True, "message": f"Kill approved for '{process_name}'"}


def get_full_whitelist() -> dict:
    """Return complete whitelist for dashboard display."""
    return {
        "critical_os": sorted(CRITICAL_OS),
        "common_safe": sorted(COMMON_SAFE),
        "user_defined": sorted(load_user_whitelist()),
        "total_protected": len(CRITICAL_OS) + len(COMMON_SAFE) + len(load_user_whitelist())
    }
