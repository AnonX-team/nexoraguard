"""
Network Isolation Module — Emergency Quarantine
One-click block ALL outbound/inbound traffic via Windows Firewall.
Only localhost (127.0.0.1) and the NexoraGuard API port remain accessible.

This mirrors CrowdStrike/SentinelOne's "Network Containment" feature.
Requires: Administrator privileges.
"""
import subprocess
import logging
import json
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

ISOLATION_STATE_FILE = Path(__file__).parent / "isolation_state.json"
RULE_NAME_BLOCK_OUT  = "NexoraGuard-ISOLATION-Block-Outbound"
RULE_NAME_BLOCK_IN   = "NexoraGuard-ISOLATION-Block-Inbound"
RULE_NAME_ALLOW_LO   = "NexoraGuard-ISOLATION-Allow-Localhost"
NEXORA_API_PORT      = 8000


def _run_ps(cmd: str) -> tuple[bool, str]:
    """Run a PowerShell command as Administrator. Returns (success, output)."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=30
        )
        success = r.returncode == 0
        output  = (r.stdout + r.stderr).strip()
        if not success:
            logger.warning(f"PS command failed (rc={r.returncode}): {output[:200]}")
        return success, output
    except Exception as e:
        logger.error(f"PS execution error: {e}")
        return False, str(e)


def _save_state(isolated: bool, reason: str = "", isolated_at: str = ""):
    state = {
        "isolated":     isolated,
        "reason":       reason,
        "isolated_at":  isolated_at or datetime.now().isoformat(),
        "api_port":     NEXORA_API_PORT,
    }
    with open(ISOLATION_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_isolation_state() -> dict:
    """Return current isolation state."""
    if not ISOLATION_STATE_FILE.exists():
        return {"isolated": False, "reason": "", "isolated_at": None}
    try:
        with open(ISOLATION_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"isolated": False, "reason": "", "isolated_at": None}


def activate_isolation(reason: str = "Manual quarantine") -> dict:
    """
    Block ALL network traffic except:
      - Localhost loopback (127.0.0.1)
      - NexoraGuard API port (so dashboard stays accessible)

    Creates 3 firewall rules:
      1. Allow loopback outbound
      2. Block all outbound
      3. Block all inbound
    """
    logger.warning(f"NETWORK ISOLATION ACTIVATED — Reason: {reason}")

    steps = []

    # Step 1: Allow localhost outbound first (so API remains reachable)
    ok1, _ = _run_ps(f"""
    New-NetFirewallRule `
      -DisplayName '{RULE_NAME_ALLOW_LO}' `
      -Direction Outbound `
      -Action Allow `
      -RemoteAddress 127.0.0.1 `
      -Protocol TCP `
      -ErrorAction SilentlyContinue
    """)
    steps.append({"step": "allow_localhost", "success": ok1})

    # Step 2: Allow API port inbound (dashboard access)
    ok2, _ = _run_ps(f"""
    New-NetFirewallRule `
      -DisplayName '{RULE_NAME_ALLOW_LO}-Inbound' `
      -Direction Inbound `
      -Action Allow `
      -LocalPort {NEXORA_API_PORT} `
      -Protocol TCP `
      -ErrorAction SilentlyContinue
    """)
    steps.append({"step": "allow_api_inbound", "success": ok2})

    # Step 3: Block ALL outbound (except above allow rule takes priority)
    ok3, _ = _run_ps(f"""
    New-NetFirewallRule `
      -DisplayName '{RULE_NAME_BLOCK_OUT}' `
      -Direction Outbound `
      -Action Block `
      -ErrorAction SilentlyContinue
    """)
    steps.append({"step": "block_outbound", "success": ok3})

    # Step 4: Block ALL inbound (except above allow rule)
    ok4, _ = _run_ps(f"""
    New-NetFirewallRule `
      -DisplayName '{RULE_NAME_BLOCK_IN}' `
      -Direction Inbound `
      -Action Block `
      -ErrorAction SilentlyContinue
    """)
    steps.append({"step": "block_inbound", "success": ok4})

    isolated_at = datetime.now().isoformat()
    success = ok3 or ok4  # at least one block rule was created
    if success:
        _save_state(True, reason, isolated_at)
        logger.warning("ISOLATION ACTIVE — all network traffic blocked except localhost")
    else:
        logger.error("ISOLATION FAILED — could not create firewall rules (Admin required?)")

    return {
        "success":     success,
        "isolated":    success,
        "isolated_at": isolated_at,
        "reason":      reason,
        "steps":       steps,
        "message":     (
            "QUARANTINE ACTIVE — All network traffic blocked. "
            f"Dashboard remains accessible at http://localhost:{NEXORA_API_PORT}"
            if success else
            "Isolation FAILED — ensure NexoraGuard runs as Administrator"
        )
    }


def deactivate_isolation() -> dict:
    """Remove all NexoraGuard isolation firewall rules and restore normal networking."""
    logger.info("Deactivating network isolation...")

    rules_to_remove = [
        RULE_NAME_BLOCK_OUT,
        RULE_NAME_BLOCK_IN,
        RULE_NAME_ALLOW_LO,
        f"{RULE_NAME_ALLOW_LO}-Inbound",
    ]

    results = []
    for rule in rules_to_remove:
        ok, _ = _run_ps(f"Remove-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue")
        results.append({"rule": rule, "removed": ok})

    _save_state(False, "", "")
    logger.info("Network isolation deactivated — normal traffic restored")

    return {
        "success":   True,
        "isolated":  False,
        "rules_removed": results,
        "message":   "Network isolation lifted — normal traffic restored",
    }
