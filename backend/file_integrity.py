"""
File Integrity Monitor
Tracks SHA-256 hash changes of critical system files.
Supports 50+ built-in critical paths + user-configurable custom paths.
"""
import hashlib
import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

BASELINE_FILE    = Path(__file__).parent / "file_baseline.json"
CUSTOM_PATHS_FILE = Path(__file__).parent / "custom_monitored_paths.json"

# ── Built-in critical files (50+) ────────────────────────────────────────────
BUILTIN_MONITORED_PATHS = [
    # Network & hosts
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/drivers/etc/lmhosts.sam",
    "C:/Windows/System32/drivers/etc/networks",
    "C:/Windows/System32/drivers/etc/protocol",
    "C:/Windows/System32/drivers/etc/services",

    # Core OS executables
    "C:/Windows/System32/cmd.exe",
    "C:/Windows/System32/powershell.exe",
    "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "C:/Windows/System32/notepad.exe",
    "C:/Windows/System32/taskmgr.exe",
    "C:/Windows/System32/regedit.exe",
    "C:/Windows/System32/mmc.exe",
    "C:/Windows/System32/mshta.exe",
    "C:/Windows/System32/wscript.exe",
    "C:/Windows/System32/cscript.exe",
    "C:/Windows/System32/rundll32.exe",
    "C:/Windows/System32/regsvr32.exe",
    "C:/Windows/System32/svchost.exe",
    "C:/Windows/System32/lsass.exe",
    "C:/Windows/System32/services.exe",
    "C:/Windows/System32/winlogon.exe",
    "C:/Windows/System32/csrss.exe",
    "C:/Windows/System32/smss.exe",
    "C:/Windows/System32/explorer.exe",
    "C:/Windows/explorer.exe",

    # Security & auth
    "C:/Windows/System32/secur32.dll",
    "C:/Windows/System32/samlib.dll",
    "C:/Windows/System32/ntdll.dll",
    "C:/Windows/System32/kernel32.dll",
    "C:/Windows/System32/advapi32.dll",
    "C:/Windows/System32/msvcrt.dll",
    "C:/Windows/System32/netapi32.dll",

    # Network tools (often abused)
    "C:/Windows/System32/net.exe",
    "C:/Windows/System32/net1.exe",
    "C:/Windows/System32/netsh.exe",
    "C:/Windows/System32/ipconfig.exe",
    "C:/Windows/System32/nslookup.exe",
    "C:/Windows/System32/ping.exe",
    "C:/Windows/System32/tracert.exe",
    "C:/Windows/System32/ftp.exe",
    "C:/Windows/System32/telnet.exe",

    # Task & service management
    "C:/Windows/System32/sc.exe",
    "C:/Windows/System32/schtasks.exe",
    "C:/Windows/System32/at.exe",

    # WMI / scripting (common attack vectors)
    "C:/Windows/System32/wbem/wmic.exe",
    "C:/Windows/System32/wbem/wmiprvse.exe",
    "C:/Windows/System32/certutil.exe",
    "C:/Windows/System32/bitsadmin.exe",

    # Boot & MBR
    "C:/Windows/System32/bootcfg.exe",
    "C:/Windows/System32/bcdedit.exe",
]


def _load_custom_paths() -> list[str]:
    """Load user-defined paths from custom_monitored_paths.json."""
    if not CUSTOM_PATHS_FILE.exists():
        return []
    try:
        with open(CUSTOM_PATHS_FILE) as f:
            data = json.load(f)
            return data.get("paths", [])
    except Exception:
        return []


def _save_custom_paths(paths: list[str]):
    """Save user-defined paths to disk."""
    with open(CUSTOM_PATHS_FILE, "w") as f:
        json.dump({"paths": paths, "updated_at": datetime.now().isoformat()}, f, indent=2)


def get_all_monitored_paths() -> list[str]:
    """Return combined list: builtin + user-defined, deduplicated."""
    custom = _load_custom_paths()
    combined = list(dict.fromkeys(BUILTIN_MONITORED_PATHS + custom))  # preserve order, dedup
    return combined


def add_monitored_path(path: str) -> dict:
    """Add a custom path to the monitored list."""
    path = path.replace("\\", "/").strip()
    custom = _load_custom_paths()
    all_paths = [p.lower() for p in BUILTIN_MONITORED_PATHS + custom]
    if path.lower() in all_paths:
        return {"success": False, "message": f"Path already monitored: {path}"}
    if not Path(path).exists():
        return {"success": False, "message": f"Path does not exist: {path}"}
    custom.append(path)
    _save_custom_paths(custom)
    logger.info(f"Added custom monitored path: {path}")
    return {"success": True, "message": f"Now monitoring: {path}", "total": len(get_all_monitored_paths())}


def remove_monitored_path(path: str) -> dict:
    """Remove a user-defined path (cannot remove builtins)."""
    path = path.replace("\\", "/").strip()
    builtin_lower = [p.lower() for p in BUILTIN_MONITORED_PATHS]
    if path.lower() in builtin_lower:
        return {"success": False, "message": "Cannot remove built-in critical path"}
    custom = _load_custom_paths()
    new_custom = [p for p in custom if p.lower() != path.lower()]
    if len(new_custom) == len(custom):
        return {"success": False, "message": f"Path not found in custom list: {path}"}
    _save_custom_paths(new_custom)
    logger.info(f"Removed custom monitored path: {path}")
    return {"success": True, "message": f"Removed: {path}", "total": len(BUILTIN_MONITORED_PATHS) + len(new_custom)}


def get_paths_info() -> dict:
    """Return metadata about monitored paths."""
    custom = _load_custom_paths()
    all_paths = get_all_monitored_paths()
    accessible = sum(1 for p in all_paths if Path(p).exists())
    return {
        "total": len(all_paths),
        "builtin": len(BUILTIN_MONITORED_PATHS),
        "custom": len(custom),
        "accessible": accessible,
        "inaccessible": len(all_paths) - accessible,
        "builtin_paths": BUILTIN_MONITORED_PATHS,
        "custom_paths": custom,
    }


# ── Hashing ───────────────────────────────────────────────────────────────────

def file_hash(path: str) -> str | None:
    """Compute SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.debug(f"Cannot hash {path}: {e}")
        return None


# ── Baseline management ───────────────────────────────────────────────────────

def create_baseline() -> dict:
    """Create hash baseline for all monitored files (builtin + custom)."""
    baseline = {}
    all_paths = get_all_monitored_paths()
    hashed = 0
    for path in all_paths:
        h = file_hash(path)
        if h:
            baseline[path] = {
                "hash": h,
                "timestamp": datetime.now().isoformat(),
                "builtin": path in BUILTIN_MONITORED_PATHS
            }
            hashed += 1

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    logger.info(f"Baseline created: {hashed}/{len(all_paths)} files hashed")
    return baseline


def load_baseline() -> dict:
    """Load existing baseline or create new one."""
    if not BASELINE_FILE.exists():
        logger.info("No baseline found — creating new baseline")
        return create_baseline()
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except Exception:
        return create_baseline()


def update_baseline_for_path(path: str) -> dict:
    """Add a single new path to existing baseline without full rebuild."""
    baseline = load_baseline()
    h = file_hash(path)
    if not h:
        return {"success": False, "message": f"Cannot hash: {path}"}
    baseline[path] = {
        "hash": h,
        "timestamp": datetime.now().isoformat(),
        "builtin": path in BUILTIN_MONITORED_PATHS
    }
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    return {"success": True, "message": f"Baseline updated for: {path}"}


# ── Integrity check ───────────────────────────────────────────────────────────

def check_integrity() -> list[dict]:
    """
    Compare current hashes with baseline.
    Only checks files that exist in baseline AND are in current monitored list.
    Returns list of violations (MODIFIED or INACCESSIBLE).
    """
    baseline  = load_baseline()
    all_paths = set(p.lower() for p in get_all_monitored_paths())
    violations = []

    for path, info in baseline.items():
        # Skip paths no longer in monitored list
        if path.lower() not in all_paths:
            continue

        current_hash = file_hash(path)
        if current_hash is None:
            violations.append({
                "path": path,
                "status": "INACCESSIBLE",
                "severity": "MEDIUM",
                "builtin": info.get("builtin", True),
                "message": f"Cannot read file: {path}",
                "timestamp": datetime.now().isoformat()
            })
        elif current_hash != info["hash"]:
            violations.append({
                "path": path,
                "status": "MODIFIED",
                "severity": "CRITICAL",
                "builtin": info.get("builtin", True),
                "message": f"File modified: {path}",
                "expected_hash": info["hash"][:16] + "...",
                "current_hash": current_hash[:16] + "...",
                "baseline_time": info["timestamp"],
                "timestamp": datetime.now().isoformat()
            })

    return violations
