"""
Windows Event Log Collector
Fetches Security, System, PowerShell, and Application logs via PowerShell.
Covers 12 event categories including new persistence, evasion, and lateral movement indicators.
"""
import subprocess
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def run_powershell(command: str, timeout: int = 45) -> str:
    """Execute a PowerShell command and return output."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.error("PowerShell command timed out")
        return ""
    except Exception as e:
        logger.error(f"PowerShell error: {e}")
        return ""


def _parse_events(output: str) -> list[dict]:
    """Parse JSON output from Get-WinEvent. Handles single-object and array responses."""
    if not output:
        return []
    try:
        events = json.loads(output)
        if isinstance(events, dict):
            events = [events]
        return events if isinstance(events, list) else []
    except json.JSONDecodeError:
        return []


# ── Core Security Events ──────────────────────────────────────────────────────

def get_security_events(count: int = 200) -> list[dict]:
    """Fetch recent Security log events."""
    command = f"""
    Get-WinEvent -LogName Security -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


def get_failed_logins(count: int = 100) -> list[dict]:
    """Event 4625 — Failed login attempts (brute force indicator)."""
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


def get_new_accounts(count: int = 50) -> list[dict]:
    """Event 4720 — New user account creation."""
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4720}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


def get_privilege_escalations(count: int = 50) -> list[dict]:
    """Event 4672 — Special privileges assigned (privilege escalation)."""
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4672}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


def get_powershell_events(count: int = 100) -> list[dict]:
    """Event 4104 — Suspicious PowerShell script execution (script block logging)."""
    command = f"""
    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


# ── NEW: Persistence Indicators ───────────────────────────────────────────────

def get_scheduled_task_events(count: int = 50) -> list[dict]:
    """
    Events 4698/4702 — Scheduled task created or modified.
    Attackers use scheduled tasks for persistence.
    """
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4698,4702}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


def get_service_install_events(count: int = 50) -> list[dict]:
    """
    Event 7045 (System log) + 4697 (Security log) — New service installed.
    Malware commonly installs itself as a Windows service.
    """
    # Event 7045 from System log
    cmd_system = f"""
    Get-WinEvent -FilterHashtable @{{LogName='System'; Id=7045}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    # Event 4697 from Security log
    cmd_security = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4697}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    events = _parse_events(run_powershell(cmd_system)) + _parse_events(run_powershell(cmd_security))
    return events


def get_process_creation_events(count: int = 100) -> list[dict]:
    """
    Event 4688 — New process created.
    Critical for detecting cmd.exe, powershell.exe, wscript.exe spawned from unusual parents.
    Requires 'Audit Process Creation' policy to be enabled.
    """
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4688}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


# ── NEW: Evasion & Covering Tracks ────────────────────────────────────────────

def get_log_cleared_events(count: int = 20) -> list[dict]:
    """
    Events 1102 (Security log cleared) + 104 (System log cleared).
    Extremely high severity — attackers clear logs to hide activity.
    """
    cmd_security = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=1102}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    cmd_system = f"""
    Get-WinEvent -FilterHashtable @{{LogName='System'; Id=104}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    events = _parse_events(run_powershell(cmd_security)) + _parse_events(run_powershell(cmd_system))
    return events


# ── NEW: Lateral Movement ─────────────────────────────────────────────────────

def get_explicit_logon_events(count: int = 50) -> list[dict]:
    """
    Event 4648 — Logon attempted with explicit credentials.
    Indicator of lateral movement, pass-the-hash, or credential stuffing.
    """
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4648}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


def get_account_lockout_events(count: int = 50) -> list[dict]:
    """
    Event 4740 — Account locked out.
    Indicates brute force attack exceeded threshold.
    """
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4740}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


def get_remote_logon_events(count: int = 50) -> list[dict]:
    """
    Event 4624 with LogonType 3/10 — Network/Remote logon.
    Used to track remote access attempts (RDP, SMB, WinRM).
    """
    command = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624}} -MaxEvents {count} -ErrorAction SilentlyContinue |
    Where-Object {{$_.Message -match 'Logon Type:\\s+(3|10)'}} |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    return _parse_events(run_powershell(command))


# ── Main collector ────────────────────────────────────────────────────────────

def collect_all_logs(count: int = 200) -> dict:
    """
    Collect all 12 log categories and return as structured dict.
    Fast path: each category is fetched independently so one failure doesn't block others.
    """
    timestamp = datetime.now().isoformat()

    # Run all collectors — failures return [] silently
    result = {
        "timestamp": timestamp,

        # ── Core (always collected) ──────────────────────────────────────────
        "security_events":       get_security_events(count),
        "failed_logins":         get_failed_logins(min(count, 100)),
        "new_accounts":          get_new_accounts(50),
        "privilege_escalations": get_privilege_escalations(50),
        "powershell_events":     get_powershell_events(min(count, 100)),

        # ── Persistence detection ────────────────────────────────────────────
        "scheduled_task_events": get_scheduled_task_events(50),
        "service_install_events": get_service_install_events(50),
        "process_creation_events": get_process_creation_events(min(count, 100)),

        # ── Evasion detection ────────────────────────────────────────────────
        "log_cleared_events":    get_log_cleared_events(20),

        # ── Lateral movement ─────────────────────────────────────────────────
        "explicit_logon_events": get_explicit_logon_events(50),
        "account_lockout_events": get_account_lockout_events(50),
        "remote_logon_events":   get_remote_logon_events(50),
    }

    # Summary counts for quick inspection
    result["_summary"] = {
        cat: len(events)
        for cat, events in result.items()
        if isinstance(events, list)
    }

    return result
