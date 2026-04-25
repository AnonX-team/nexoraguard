"""
USB / Removable Device Monitor
Detects USB insertions and removable media events via Windows Event Log.

Event sources:
  - Microsoft-Windows-DriverFrameworks-UserMode/Operational (Event 2003, 2100, 2101)
  - Microsoft-Windows-WPD-MTPClassDriver/Operational (MTP devices)
  - System log (Event 20001 — new device)

MITRE ATT&CK: T1091 — Replication Through Removable Media
"""
import subprocess
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _run_ps(cmd: str) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout.strip()
    except Exception as e:
        logger.debug(f"USB monitor PS error: {e}")
        return ""


def _parse(output: str) -> list[dict]:
    if not output:
        return []
    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except Exception:
        return []


def get_usb_events(count: int = 50) -> list[dict]:
    """
    Fetch recent USB device connection events.
    Tries multiple event sources for maximum coverage.
    """
    events = []

    # Source 1: DriverFrameworks-UserMode (USB device lifecycle)
    cmd1 = f"""
    Get-WinEvent -LogName 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' `
      -MaxEvents {count} -ErrorAction SilentlyContinue |
    Where-Object {{$_.Id -in 2003,2100,2101,2004}} |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    events.extend(_parse(_run_ps(cmd1)))

    # Source 2: System log — new hardware device (Event 20001)
    cmd2 = f"""
    Get-WinEvent -FilterHashtable @{{LogName='System'; Id=20001}} `
      -MaxEvents {count} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    events.extend(_parse(_run_ps(cmd2)))

    # Source 3: Security log — removable storage access (Event 4663 with Object Type=Removable Storage)
    cmd3 = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4663}} `
      -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object {{$_.Message -match 'Removable Storage'}} |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Depth 2
    """
    events.extend(_parse(_run_ps(cmd3)))

    return events[:count]


def analyze_usb_events(events: list[dict]) -> list[dict]:
    """
    Process raw USB events into structured alert-ready dicts.
    """
    alerts = []
    seen_times = set()

    for event in events:
        ts  = str(event.get("TimeCreated", ""))
        eid = str(event.get("Id", ""))
        msg = event.get("Message", "")

        # Deduplicate by timestamp
        if ts in seen_times:
            continue
        seen_times.add(ts)

        # Classify event type
        if eid in ("2003", "2100"):
            event_type = "USB_CONNECTED"
            severity   = "MEDIUM"
            description = "USB/Removable device connected"
        elif eid in ("2101", "2004"):
            event_type = "USB_DISCONNECTED"
            severity   = "LOW"
            description = "USB/Removable device disconnected"
        elif eid == "20001":
            event_type = "NEW_DEVICE"
            severity   = "MEDIUM"
            description = "New hardware device installed"
        elif eid == "4663":
            event_type = "STORAGE_ACCESS"
            severity   = "HIGH"
            description = "Removable storage accessed (possible data exfil)"
        else:
            event_type = "USB_EVENT"
            severity   = "LOW"
            description = f"USB event (ID {eid})"

        # Try to extract device name from message
        device_name = ""
        import re
        match = re.search(r"(USB|Drive|Disk|Volume|Storage)[^\n]{0,60}", msg, re.IGNORECASE)
        if match:
            device_name = match.group(0).strip()[:60]

        alerts.append({
            "event_type":   event_type,
            "severity":     severity,
            "description":  description,
            "device_name":  device_name,
            "event_id":     eid,
            "timestamp":    ts,
            "mitre": {
                "tactic":    "Initial Access",
                "tactic_id": "TA0001",
                "technique": "T1091",
                "sub_tech":  None,
                "tech_name": "Replication Through Removable Media",
                "url":       "https://attack.mitre.org/techniques/T1091/",
                "color":     "#f97316",
            }
        })

    return alerts


def check_usb_activity() -> dict:
    """Main entry point — check for recent USB activity."""
    events = get_usb_events(50)
    alerts = analyze_usb_events(events)

    connection_events = [a for a in alerts if a["event_type"] in ("USB_CONNECTED", "NEW_DEVICE")]
    high_risk         = [a for a in alerts if a["severity"] in ("HIGH", "CRITICAL")]

    return {
        "checked_at":         datetime.now().isoformat(),
        "total_events":       len(alerts),
        "connection_events":  len(connection_events),
        "high_risk_events":   len(high_risk),
        "has_activity":       len(connection_events) > 0,
        "events":             alerts,
    }
