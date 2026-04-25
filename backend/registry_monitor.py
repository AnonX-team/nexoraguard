"""
Registry Startup Monitor
Detects unauthorized apps adding themselves to Windows Startup via Registry.
Monitors all common startup registry keys and alerts on new/changed entries.
"""
import json
import logging
import winreg
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)
REGISTRY_BASELINE_FILE = Path(__file__).parent / "registry_baseline.json"

# All startup registry keys to monitor
STARTUP_KEYS = [
    # System-wide (all users)
    (winreg.HKEY_LOCAL_MACHINE,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE,  r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),

    # Current user only
    (winreg.HKEY_CURRENT_USER,   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,   r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),

    # Scheduled tasks via registry
    (winreg.HKEY_LOCAL_MACHINE,  r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
]

# Known legitimate startup entries (won't be flagged)
KNOWN_SAFE_ENTRIES = {
    "securityhealth", "windowsdefender", "onedrive", "teams", "discord",
    "steam", "nvidia", "amd", "intel", "realtek", "synaptics",
    "dropbox", "googledrivesync", "zoom", "slack",
    "nexoraguard",   # our own app
}

HIVE_NAMES = {
    winreg.HKEY_LOCAL_MACHINE: "HKLM",
    winreg.HKEY_CURRENT_USER:  "HKCU",
}


def read_startup_key(hive, subkey: str) -> dict:
    """Read all values from a registry key. Returns {name: value}."""
    entries = {}
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                entries[name] = value
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass
    except PermissionError:
        logger.debug(f"No permission to read: {HIVE_NAMES.get(hive, '?')}\\{subkey}")
    except Exception as e:
        logger.debug(f"Registry read error {subkey}: {e}")
    return entries


def scan_all_startup_entries() -> dict:
    """Scan all startup registry keys and return full snapshot."""
    snapshot = {}
    for hive, subkey in STARTUP_KEYS:
        key_path = f"{HIVE_NAMES.get(hive, '?')}\\{subkey}"
        entries = read_startup_key(hive, subkey)
        if entries:
            snapshot[key_path] = entries
    return snapshot


def save_baseline():
    """Save current registry state as trusted baseline."""
    snapshot = scan_all_startup_entries()
    baseline = {
        "created_at": datetime.now().isoformat(),
        "snapshot": snapshot
    }
    with open(REGISTRY_BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    total = sum(len(v) for v in snapshot.values())
    logger.info(f"Registry baseline saved — {total} startup entries")
    return {"created_at": baseline["created_at"], "total_entries": total, "snapshot": snapshot}


def load_baseline() -> dict:
    """Load saved baseline or create new one."""
    if not REGISTRY_BASELINE_FILE.exists():
        logger.info("No registry baseline — creating now")
        return save_baseline()
    try:
        with open(REGISTRY_BASELINE_FILE) as f:
            return json.load(f)
    except Exception:
        return save_baseline()


def _is_known_safe(name: str, value: str) -> bool:
    """Check if a startup entry is from a known safe application."""
    name_lower = name.lower()
    value_lower = value.lower()
    for safe in KNOWN_SAFE_ENTRIES:
        if safe in name_lower or safe in value_lower:
            return True
    return False


def check_registry() -> dict:
    """
    Compare current registry against baseline.
    Returns: new entries, removed entries, modified entries, and flagged threats.
    """
    baseline_data = load_baseline()
    baseline = baseline_data.get("snapshot", {})
    current  = scan_all_startup_entries()

    new_entries      = []
    removed_entries  = []
    modified_entries = []
    threats          = []

    all_keys = set(baseline.keys()) | set(current.keys())

    for key_path in all_keys:
        base_vals = baseline.get(key_path, {})
        curr_vals = current.get(key_path, {})

        # New entries added since baseline
        for name, value in curr_vals.items():
            if name not in base_vals:
                entry = {
                    "key": key_path,
                    "name": name,
                    "value": value,
                    "type": "NEW",
                    "known_safe": _is_known_safe(name, value),
                    "detected_at": datetime.now().isoformat()
                }
                new_entries.append(entry)
                if not entry["known_safe"]:
                    threats.append({
                        **entry,
                        "severity": "HIGH",
                        "message": f"Unknown app added to startup: '{name}' → {value[:80]}"
                    })

            # Modified entries
            elif base_vals[name] != value:
                entry = {
                    "key": key_path,
                    "name": name,
                    "old_value": base_vals[name],
                    "new_value": value,
                    "type": "MODIFIED",
                    "known_safe": _is_known_safe(name, value),
                    "detected_at": datetime.now().isoformat()
                }
                modified_entries.append(entry)
                if not entry["known_safe"]:
                    threats.append({
                        **entry,
                        "severity": "CRITICAL",
                        "message": f"Startup entry modified: '{name}' value changed"
                    })

        # Removed entries
        for name, value in base_vals.items():
            if name not in curr_vals:
                removed_entries.append({
                    "key": key_path,
                    "name": name,
                    "value": value,
                    "type": "REMOVED",
                    "detected_at": datetime.now().isoformat()
                })

    return {
        "checked_at": datetime.now().isoformat(),
        "baseline_created": baseline_data.get("created_at", "unknown"),
        "new_entries": new_entries,
        "removed_entries": removed_entries,
        "modified_entries": modified_entries,
        "threats": threats,
        "threat_count": len(threats),
        "clean": len(threats) == 0,
        "total_current_entries": sum(len(v) for v in current.values()),
    }


def remove_startup_entry(key_path: str, name: str) -> dict:
    """Remove a suspicious startup registry entry."""
    hive_map = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    parts = key_path.split("\\", 1)
    if len(parts) != 2 or parts[0] not in hive_map:
        return {"success": False, "message": "Invalid key path"}
    try:
        key = winreg.OpenKey(hive_map[parts[0]], parts[1], 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
        logger.warning(f"Removed startup entry: {key_path}\\{name}")
        return {"success": True, "message": f"Startup entry '{name}' removed from registry"}
    except PermissionError:
        return {"success": False, "message": "Access denied — run as Administrator"}
    except FileNotFoundError:
        return {"success": False, "message": f"Entry '{name}' not found"}
    except Exception as e:
        return {"success": False, "message": str(e)}
