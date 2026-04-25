"""
Brute Force Guard
Detects failed login attempts, extracts source IPs, auto-blocks via Windows Firewall
"""
import re
import json
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

BLOCK_LOG = Path(__file__).parent / "blocked_ips.json"
RULE_PREFIX = "NexoraGuard_Block_"
BLOCK_THRESHOLD = 5        # block after N failed attempts
WINDOW_MINUTES = 10        # within this time window


# ── Firewall Control ──────────────────────────────────────────────────────────

def _run_ps(cmd: str) -> tuple[str, str]:
    """Run PowerShell command, return (stdout, stderr)."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=15
    )
    return result.stdout.strip(), result.stderr.strip()


def block_ip(ip: str, reason: str = "Brute Force") -> dict:
    """Add Windows Firewall rule to block an IP (inbound + outbound)."""
    if not _is_valid_ip(ip):
        return {"success": False, "message": f"Invalid IP: {ip}"}

    rule_name = f"{RULE_PREFIX}{ip.replace('.', '_')}"

    # Check if already blocked
    blocked = load_blocked_ips()
    if ip in blocked:
        return {"success": False, "message": f"{ip} is already blocked"}

    # Add firewall rule (inbound block)
    cmd = (
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction Inbound -Action Block '
        f'-RemoteAddress "{ip}" -Protocol Any -Enabled True'
    )
    stdout, stderr = _run_ps(cmd)

    if stderr and "Error" in stderr:
        # Fallback to netsh if PowerShell fails
        netsh_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
        result = subprocess.run(netsh_cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return {"success": False, "message": f"Firewall block failed: {result.stderr}"}

    # Save to log
    entry = {
        "ip": ip,
        "reason": reason,
        "blocked_at": datetime.now().isoformat(),
        "rule_name": rule_name,
        "active": True
    }
    blocked[ip] = entry
    _save_blocked_ips(blocked)

    logger.warning(f"BLOCKED IP: {ip} — Reason: {reason}")
    return {"success": True, "message": f"IP {ip} blocked successfully", "entry": entry}


def unblock_ip(ip: str) -> dict:
    """Remove firewall rule to unblock an IP."""
    if not _is_valid_ip(ip):
        return {"success": False, "message": f"Invalid IP: {ip}"}

    rule_name = f"{RULE_PREFIX}{ip.replace('.', '_')}"

    # Try PowerShell first
    cmd = f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
    _run_ps(cmd)

    # Also try netsh
    netsh_cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    subprocess.run(netsh_cmd, shell=True, capture_output=True, text=True)

    # Update log
    blocked = load_blocked_ips()
    if ip in blocked:
        blocked[ip]["active"] = False
        blocked[ip]["unblocked_at"] = datetime.now().isoformat()
        _save_blocked_ips(blocked)

    logger.info(f"UNBLOCKED IP: {ip}")
    return {"success": True, "message": f"IP {ip} unblocked successfully"}


def get_active_blocked_ips() -> list[dict]:
    """Return list of currently blocked IPs."""
    blocked = load_blocked_ips()
    return [v for v in blocked.values() if v.get("active")]


def get_all_blocked_ips() -> list[dict]:
    """Return full history of blocked IPs."""
    return list(load_blocked_ips().values())


def load_blocked_ips() -> dict:
    if not BLOCK_LOG.exists():
        return {}
    try:
        with open(BLOCK_LOG) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_blocked_ips(data: dict):
    with open(BLOCK_LOG, "w") as f:
        json.dump(data, f, indent=2)


def _is_valid_ip(ip: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


# ── Failed Login Analysis ─────────────────────────────────────────────────────

def get_failed_login_ips(max_events: int = 100) -> dict:
    """
    Parse Windows Security Event Log (ID 4625) to extract source IPs.
    Returns dict: {ip: [list of timestamps]}
    """
    cmd = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents {max_events} -ErrorAction SilentlyContinue |
    ForEach-Object {{
        $msg = $_.Message
        $ip = if ($msg -match 'Source Network Address:\\s+(\\S+)') {{ $matches[1] }} else {{ 'N/A' }}
        $time = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
        "$time|$ip"
    }}
    """
    stdout, _ = _run_ps(cmd)
    if not stdout:
        return {}

    ip_attempts = defaultdict(list)
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if "|" not in line:
            continue
        parts = line.split("|", 1)
        if len(parts) == 2:
            timestamp, ip = parts
            ip = ip.strip()
            if ip and ip not in ("N/A", "-", "::1", "127.0.0.1", "LOCAL"):
                ip_attempts[ip].append(timestamp.strip())

    return dict(ip_attempts)


def analyze_brute_force() -> dict:
    """
    Analyze failed logins within time window.
    Returns attackers + auto-blocks if threshold exceeded.
    """
    ip_attempts = get_failed_login_ips(200)
    now = datetime.now()
    window_start = now - timedelta(minutes=WINDOW_MINUTES)

    attackers = []
    auto_blocked = []

    for ip, timestamps in ip_attempts.items():
        # Filter to recent window
        recent = []
        for ts in timestamps:
            try:
                t = datetime.fromisoformat(ts)
                if t >= window_start:
                    recent.append(ts)
            except Exception:
                continue

        if not recent:
            continue

        count = len(recent)
        is_blocked = ip in load_blocked_ips() and load_blocked_ips()[ip].get("active")

        attacker = {
            "ip": ip,
            "attempt_count": count,
            "recent_attempts": count,
            "first_seen": min(timestamps),
            "last_seen": max(timestamps),
            "is_blocked": is_blocked,
            "severity": "CRITICAL" if count >= 20 else "HIGH" if count >= 10 else "MEDIUM"
        }
        attackers.append(attacker)

        # Auto-block if over threshold and not already blocked
        if count >= BLOCK_THRESHOLD and not is_blocked:
            result = block_ip(ip, reason=f"Auto-blocked: {count} failed logins in {WINDOW_MINUTES}min")
            if result["success"]:
                auto_blocked.append(ip)
                attacker["is_blocked"] = True
                attacker["just_blocked"] = True

    attackers.sort(key=lambda x: x["attempt_count"], reverse=True)

    return {
        "timestamp": now.isoformat(),
        "window_minutes": WINDOW_MINUTES,
        "threshold": BLOCK_THRESHOLD,
        "total_attackers": len(attackers),
        "auto_blocked_this_scan": auto_blocked,
        "attackers": attackers,
        "active_blocks": len(get_active_blocked_ips()),
    }
